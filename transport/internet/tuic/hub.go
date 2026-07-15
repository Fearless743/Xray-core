package tuic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/tuic"
	"github.com/xtls/xray-core/proxy/tuic/account"
	tuicCtx "github.com/xtls/xray-core/proxy/tuic/ctx"
	"github.com/xtls/xray-core/transport/internet"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

const (
	serverMaxIncomingStreams = (1 << 32) - 1
	defaultAuthTimeout       = 3 * time.Second
	defaultMaxIdleTimeout    = 15 * time.Second
	defaultMaxUDPRelaySize   = 1500
)

type Listener struct {
	ctx      context.Context
	pktConn  net.PacketConn
	listener *quic.Listener
	addConn  internet.ConnHandler
	config   *Config
	validator *account.Validator
}

func (l *Listener) Addr() net.Addr  { return l.listener.Addr() }
func (l *Listener) Close() error {
	err := l.listener.Close()
	_ = l.pktConn.Close()
	return err
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "tuic: failed to accept QUIC connection")
			return
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) handleConn(qconn *quic.Conn) {
	h := &connHandler{
		qconn:     qconn,
		addConn:   l.addConn,
		validator: l.validator,
		authCh:    make(chan struct{}),
		udpMap:    make(map[uint16]*UDPConn),
	}
	// Auth timeout
	authTimeout := defaultAuthTimeout
	if l.config.AuthTimeoutMs > 0 {
		authTimeout = time.Duration(l.config.AuthTimeoutMs) * time.Millisecond
	}
	timer := time.AfterFunc(authTimeout, func() {
		h.authOnce.Do(func() {
			_ = qconn.CloseWithError(quic.ApplicationErrorCode(tuic.AuthenticationTimeout), "AuthenticationTimeout")
			h.authOk.Store(false)
			close(h.authCh)
		})
	})

	// Handle uni-streams (auth + UDP-over-QUIC) and bidi streams (TCP) and datagrams
	go h.acceptUniStreams(timer)
	go h.acceptStreams()
	go h.acceptDatagrams()
}

type connHandler struct {
	qconn     *quic.Conn
	addConn   internet.ConnHandler
	validator *account.Validator

	authCh   chan struct{}
	authOk   atomic.Bool
	authUser atomic.Value // *protocol.MemoryUser
	authOnce sync.Once

	udpMu  sync.Mutex
	udpMap map[uint16]*UDPConn
}

func (h *connHandler) acceptUniStreams(authTimer *time.Timer) {
	for {
		stream, err := h.qconn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go h.handleUniStream(stream, authTimer)
	}
}

func (h *connHandler) handleUniStream(stream *quic.ReceiveStream, authTimer *time.Timer) {
	reader := bufio.NewReader(stream)
	head, err := tuic.ReadCommandHead(reader)
	if err != nil {
		return
	}
	switch head.TYPE {
	case tuic.CmdAuthenticate:
		auth, err := tuic.ReadAuthenticateWithHead(head, reader)
		if err != nil {
			return
		}
		authTimer.Stop()
		ok := false
		var user *protocol.MemoryUser
		if h.validator != nil {
			password, found := h.validator.GetPassword(auth.UUID)
			if found {
				token, err := genToken(h.qconn.ConnectionState(), auth.UUID, password)
				if err == nil && token == auth.TOKEN {
					ok = true
					user = h.validator.Get(auth.UUID)
				}
			}
		}
		h.authOnce.Do(func() {
			if !ok {
				_ = h.qconn.CloseWithError(quic.ApplicationErrorCode(tuic.AuthenticationFailed), "AuthenticationFailed")
			}
			h.authOk.Store(ok)
			if user != nil {
				h.authUser.Store(user)
			}
			close(h.authCh)
		})

	case tuic.CmdPacket:
		// UDP over unidirectional QUIC stream
		pkt, err := tuic.ReadPacketWithHead(head, reader)
		if err != nil {
			return
		}
		h.handlePacket(pkt)

	case tuic.CmdDissociate:
		dis, err := tuic.ReadDissociateWithHead(head, reader)
		if err != nil {
			return
		}
		h.udpMu.Lock()
		if c, ok := h.udpMap[dis.ASSOC_ID]; ok {
			delete(h.udpMap, dis.ASSOC_ID)
			c.Close()
		}
		h.udpMu.Unlock()
	}
}

func (h *connHandler) acceptStreams() {
	for {
		stream, err := h.qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go h.handleStream(stream)
	}
}

func (h *connHandler) handleStream(stream *quic.Stream) {
	// Wait for auth
	<-h.authCh
	if !h.authOk.Load() {
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}

	reader := bufio.NewReader(stream)
	connect, err := tuic.ReadConnect(reader)
	if err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}

	dest, err := addressToDestination(connect.ADDR, net.Network_TCP)
	if err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}

	var user *protocol.MemoryUser
	if v := h.authUser.Load(); v != nil {
		user = v.(*protocol.MemoryUser)
	}

	// Wrap remaining buffered data + stream as InterConn
	conn := &bufferedInterConn{
		InterConn: InterConn{
			stream: stream,
			local:  h.qconn.LocalAddr(),
			remote: h.qconn.RemoteAddr(),
			target: dest,
			user:   user,
		},
		reader: reader,
	}
	h.addConn(conn)
}

func (h *connHandler) acceptDatagrams() {
	for {
		data, err := h.qconn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		reader := bytes.NewBuffer(data)
		head, err := tuic.ReadCommandHead(reader)
		if err != nil {
			continue
		}
		if head.TYPE != tuic.CmdPacket {
			if head.TYPE == tuic.CmdHeartbeat {
				continue
			}
			continue
		}
		pkt, err := tuic.ReadPacketWithHead(head, reader)
		if err != nil {
			continue
		}
		h.handlePacket(pkt)
	}
}

func (h *connHandler) handlePacket(pkt tuic.Packet) {
	<-h.authCh
	if !h.authOk.Load() {
		return
	}
	// Only handle non-fragmented or first complete packets for simplicity
	if pkt.FRAG_TOTAL != 0 && pkt.FRAG_TOTAL != 1 {
		// skip fragments for now (common clients send FRAG_TOTAL=1)
		if pkt.FRAG_TOTAL > 1 {
			return
		}
	}
	dest, err := addressToDestination(pkt.ADDR, net.Network_UDP)
	if err != nil {
		return
	}

	var user *protocol.MemoryUser
	if v := h.authUser.Load(); v != nil {
		user = v.(*protocol.MemoryUser)
	}

	h.udpMu.Lock()
	uc, ok := h.udpMap[pkt.ASSOC_ID]
	if !ok {
		assocID := pkt.ASSOC_ID
		uc = &UDPConn{
			local:   h.qconn.LocalAddr(),
			remote:  h.qconn.RemoteAddr(),
			user:    user,
			target:  dest,
			readCh:  make(chan udpMsg, 64),
			writeFn: h.makeUDPWriteFn(assocID),
			closeFn: func() {
				h.udpMu.Lock()
				delete(h.udpMap, assocID)
				h.udpMu.Unlock()
			},
		}
		h.udpMap[assocID] = uc
		h.udpMu.Unlock()
		// First packet - feed then hand to proxy
		uc.feed(pkt.DATA, dest)
		h.addConn(uc)
		return
	}
	h.udpMu.Unlock()
	uc.feed(pkt.DATA, dest)
}

func (h *connHandler) makeUDPWriteFn(assocID uint16) func([]byte, net.Destination) error {
	var pktID uint16
	return func(data []byte, dest net.Destination) error {
		pktID++
		addr := destinationToAddress(dest)
		pkt := tuic.NewPacket(assocID, pktID, 1, 0, addr, data)
		var buf bytes.Buffer
		// buf needs ByteWriter
		bw := &byteBuffer{Buffer: &buf}
		if err := pkt.WriteTo(bw); err != nil {
			return err
		}
		return h.qconn.SendDatagram(buf.Bytes())
	}
}

type byteBuffer struct {
	*bytes.Buffer
}

func (b *byteBuffer) WriteByte(c byte) error {
	return b.Buffer.WriteByte(c)
}

// bufferedInterConn re-attaches leftover buffered bytes before the stream body.
type bufferedInterConn struct {
	InterConn
	reader *bufio.Reader
	once   sync.Once
}

func (c *bufferedInterConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func addressToDestination(addr tuic.Address, network net.Network) (net.Destination, error) {
	host := addr.String()
	if host == "" {
		return net.Destination{}, errors.New("empty address")
	}
	prefix := "tcp:"
	if network == net.Network_UDP {
		prefix = "udp:"
	}
	return net.ParseDestination(prefix + host)
}

func destinationToAddress(dest net.Destination) tuic.Address {
	return tuic.AddressFromHostPort(dest.Address.String(), uint16(dest.Port))
}

func genToken(state quic.ConnectionState, id [16]byte, password string) ([32]byte, error) {
	var token [32]byte
	// TUIC v5 / mihomo: label = raw UUID bytes as string, context = password
	label := string(id[:])
	b, err := state.TLS.ExportKeyingMaterial(label, []byte(password), 32)
	if err != nil {
		return token, err
	}
	copy(token[:], b)
	return token, nil
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("tuic: address is domain")
	}
	tlsConfig := xtls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tuic: tls config is required")
	}
	validator := tuicCtx.ValidatorFromContext(ctx)
	if validator == nil {
		return nil, errors.New("tuic: validator is nil")
	}

	config, _ := streamSettings.ProtocolSettings.(*Config)
	if config == nil {
		config = &Config{}
	}

	raw, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	maxIdle := defaultMaxIdleTimeout
	if config.MaxIdleTimeoutMs > 0 {
		maxIdle = time.Duration(config.MaxIdleTimeoutMs) * time.Millisecond
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:        maxIdle,
		MaxIncomingStreams:    serverMaxIncomingStreams,
		MaxIncomingUniStreams: serverMaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             true,
		DisablePathManager:    true,
		MaxDatagramFrameSize:  1400,
	}

	// Ensure ALPN includes h3 for TUIC
	gotls := tlsConfig.GetTLSConfig()
	if len(gotls.NextProtos) == 0 {
		gotls.NextProtos = []string{"h3"}
	}
	// Force TLS 1.3
	if gotls.MinVersion == 0 {
		gotls.MinVersion = tls.VersionTLS13
	}

	qListener, err := quic.Listen(raw, gotls, quicConfig)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	l := &Listener{
		ctx:       ctx,
		pktConn:   raw,
		listener:  qListener,
		addConn:   handler,
		config:    config,
		validator: validator,
	}
	go l.keepAccepting()
	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}

