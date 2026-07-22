package shadowquic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/jls-quic-go"
	"github.com/metacubex/jls-tls"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/shadowquic/account"
	sqCtx "github.com/xtls/xray-core/proxy/shadowquic/ctx"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	serverMaxIncomingStreams = (1 << 32) - 1
	defaultMaxIdleTimeout    = 30 * time.Second
	defaultStreamRecvWindow  = 15 * 1024 * 1024 / 10
	defaultStreamMaxWindow   = 15 * 1024 * 1024
	defaultConnRecvWindow    = 64 * 1024 * 1024 / 10
	defaultConnMaxWindow     = 64 * 1024 * 1024
)

type Listener struct {
	ctx       context.Context
	pktConn   net.PacketConn
	listener  *quic.EarlyListener
	addConn   internet.ConnHandler
	config    *Config
	validator *account.Validator
}

func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Close() error {
	err := l.listener.Close()
	_ = l.pktConn.Close()
	return err
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "shadowquic: failed to accept QUIC connection")
			return
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) handleConn(qconn *quic.Conn) {
	state := newConnState(qconn)
	for {
		stream, err := state.quicConn.AcceptStream(state.ctx)
		if err != nil {
			state.cancel()
			return
		}
		go l.handleStream(state, stream)
	}
}

func (l *Listener) handleStream(state *connState, stream *quic.Stream) {
	// Consume command + address from the stream, then hand remaining body as InterConn.
	command, err := ReadCommand(stream)
	if err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}
	user := l.jlsUser(state)
	switch command {
	case CommandConnect:
		addr, port, err := ReadRequestAddr(stream)
		if err != nil {
			stream.CancelRead(0)
			_ = stream.Close()
			return
		}
		dest := destinationFromAddrPort(addr, port, xnet.Network_TCP)
		l.addConn(&InterConn{
			stream: stream,
			local:  state.quicConn.LocalAddr(),
			remote: state.quicConn.RemoteAddr(),
			target: dest,
			user:   user,
		})

	case CommandAssociateDatagram, CommandAssociateStream:
		if _, _, err := ReadRequestAddr(stream); err != nil {
			stream.CancelRead(0)
			_ = stream.Close()
			return
		}
		mode := udpModeDatagram
		if command == CommandAssociateStream {
			mode = udpModeStream
		}
		assoc := newAssociation(state, stream, mode)
		go l.handleAssociation(assoc, user)

	case CommandExtension, CommandBind, CommandAuthenticate:
		fallthrough
	default:
		stream.CancelRead(0)
		_ = stream.Close()
	}
}

func (l *Listener) handleAssociation(assoc *association, user *protocol.MemoryUser) {
	select {
	case packet := <-assoc.input:
		uc := &UDPConn{
			local:  assoc.parent.quicConn.LocalAddr(),
			remote: assoc.parent.quicConn.RemoteAddr(),
			user:   user,
			target: packet.dest,
			readCh: make(chan udpMsg, 64),
			writeFn: func(data []byte, dest xnet.Destination) error {
				_, err := assoc.writeTo(data, dest)
				return err
			},
			closeFn: func() {
				_ = assoc.Close()
			},
		}
		uc.feed(packet.data, packet.dest)
		go func() {
			for {
				select {
				case p := <-assoc.input:
					uc.feed(p.data, p.dest)
				case <-assoc.closed:
					_ = uc.Close()
					return
				}
			}
		}()
		l.addConn(uc)
	case <-assoc.closed:
		return
	}
}

func (l *Listener) jlsUser(state *connState) *protocol.MemoryUser {
	tlsState := state.quicConn.ConnectionState().TLS
	if tlsState.JLS.Status != tls.JLSAuthenticated {
		return nil
	}
	name := tlsState.JLS.User
	if name == "" || l.validator == nil {
		return nil
	}
	return l.validator.GetByName(name)
}

func Listen(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("shadowquic: address is domain")
	}

	validator := sqCtx.ValidatorFromContext(ctx)
	if validator == nil {
		return nil, errors.New("shadowquic: validator is nil")
	}

	config, _ := streamSettings.ProtocolSettings.(*Config)
	if config == nil {
		config = &Config{}
	}
	if strings.TrimSpace(config.JlsUpstream) == "" {
		return nil, errors.New("shadowquic: jls_upstream is required")
	}

	raw, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := buildServerTLSConfig(config, validator)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	maxIdle := defaultMaxIdleTimeout
	if config.MaxIdleTimeoutMs > 0 {
		maxIdle = time.Duration(config.MaxIdleTimeoutMs) * time.Millisecond
	}

	jlsPacketDialer := func(_ context.Context, network, address string) (net.PacketConn, net.Addr, error) {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, nil, err
		}
		ua, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			_ = pc.Close()
			return nil, nil, err
		}
		return pc, ua, nil
	}

	quicConfig := &quic.Config{
		JLSConfig: &quic.JLSConfig{
			UpstreamAddr: config.JlsUpstream,
			PacketDialer: jlsPacketDialer,
		},
		MaxIdleTimeout:                 maxIdle,
		MaxIncomingStreams:             serverMaxIncomingStreams,
		MaxIncomingUniStreams:          serverMaxIncomingStreams,
		InitialStreamReceiveWindow:     uint64(defaultStreamRecvWindow),
		MaxStreamReceiveWindow:         uint64(defaultStreamMaxWindow),
		InitialConnectionReceiveWindow: uint64(defaultConnRecvWindow),
		MaxConnectionReceiveWindow:     uint64(defaultConnMaxWindow),
		MaxDatagramFrameSize:           1400,
		EnableDatagrams:                true,
		Allow0RTT:                      config.ZeroRtt,
	}

	qListener, err := quic.ListenEarly(raw, tlsConfig, quicConfig)
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

func buildServerTLSConfig(config *Config, v *account.Validator) (*tls.Config, error) {
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	alpn := config.Alpn
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	serverName := config.ServerName
	if serverName == "" {
		serverName = defaultJLSServerName(config.JlsUpstream)
	}

	entries := v.Entries()
	users := make([]tls.JLSUser, 0, len(entries))
	for _, e := range entries {
		users = append(users, tls.JLSUser{
			Username: e.Name,
			Password: e.Password,
		})
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
		JLSConfig: &tls.JLSConfig{
			Enable:     true,
			Users:      users,
			ServerName: serverName,
		},
	}, nil
}

func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"ShadowQUIC"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * 10 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func defaultJLSServerName(upstreamAddr string) string {
	host, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		host = upstreamAddr
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	if strings.Contains(host, ":") {
		return ""
	}
	return host
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
