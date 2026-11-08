package trusttunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	stdnet "net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/trusttunnel/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/http2"
)

// Pseudo-hosts reserved by the TrustTunnel protocol (see PROTOCOL.md).
const (
	pseudoUDP   = "_udp2"
	pseudoICMP  = "_icmp"
	pseudoCheck = "_check"
)

// h2Preface is the HTTP/2 connection preface sent by clients using prior
// knowledge or H2 over TLS (after ALPN negotiates h2, the first bytes are
// always the preface).
const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// udpSessionTimeout is the idle timeout for UDP associations (spec: 120s).
const udpSessionTimeout = 120 * time.Second

// maxUDPPacket is the max reassembled UDP multiplex packet (headers + payload).
const maxUDPPacket = 128 * 1024

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get trusttunnel user").Base(err).AtError()
		}
		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}
	v := core.MustFromContext(ctx)
	return &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UNIX}
}

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return s.validator.GetCount()
}

var _ proxy.UserManager = (*Server)(nil)

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	idx := strings.IndexByte(cs, ':')
	if idx < 0 {
		return
	}
	return cs[:idx], cs[idx+1:], true
}

func (s *Server) authenticate(authHeader string) *protocol.MemoryUser {
	_, password, ok := parseBasicAuth(authHeader)
	if !ok || password == "" {
		return nil
	}
	return s.validator.GetByPassword(password)
}

// replayConn replays peeked bytes before delegating to the underlying conn.
type replayConn struct {
	stat.Connection
	reader io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "trusttunnel"
		inbound.CanSpliceCopy = 2
		if !proxy.IsRAWTransportWithoutSecurity(conn) {
			inbound.CanSpliceCopy = 3
		}
	}

	// Peek for HTTP/2 preface to decide between H1 and H2 handling.
	if err := conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		errors.LogDebugInner(ctx, err, "failed to set read deadline")
	}
	peek := make([]byte, len(h2Preface))
	if _, err := io.ReadFull(conn, peek); err != nil {
		return errors.New("failed to peek protocol").Base(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogDebugInner(ctx, err, "failed to clear read deadline")
	}
	if string(peek) == h2Preface {
		rc := &replayConn{Connection: conn, reader: io.MultiReader(bytes.NewReader(peek), conn)}
		return s.handleH2(ctx, rc, dispatcher)
	}
	rc := &replayConn{Connection: conn, reader: io.MultiReader(bytes.NewReader(peek), conn)}
	return s.handleH1(ctx, rc, dispatcher)
}

// ─── HTTP/1.1 path ──────────────────────────────────────────────────────────

func (s *Server) handleH1(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	reader := bufio.NewReaderSize(&readerOnly{conn}, buf.Size)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.policy().Timeouts.Handshake)); err != nil {
			errors.LogDebugInner(ctx, err, "failed to set read deadline")
		}
		request, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return errors.New("failed to read http request").Base(err).AtWarning()
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			errors.LogDebugInner(ctx, err, "failed to clear read deadline")
		}

		if !strings.EqualFold(request.Method, "CONNECT") {
			_, _ = conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
			return errors.New("trusttunnel: non-CONNECT method not allowed")
		}

		user := s.authenticate(request.Header.Get("Proxy-Authorization"))
		if user == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"trusttunnel\"\r\n\r\n"))
			return errors.New("trusttunnel: invalid user")
		}
		if inbound != nil {
			inbound.User = user
		}

		host := request.Host
		if host == "" {
			host = request.URL.Host
		}
		errors.LogInfo(ctx, "trusttunnel CONNECT to [", host, "]")

		switch pseudoHostOf(host) {
		case pseudoCheck:
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			return nil
		case pseudoICMP:
			_, _ = conn.Write([]byte("HTTP/1.1 502 Not Implemented\r\n\r\n"))
			return errors.New("trusttunnel: ICMP not implemented")
		case pseudoUDP:
			_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			if err != nil {
				return errors.New("failed to write back OK response").Base(err)
			}
			return s.handleUDPStream(ctx, user, &h1StreamReader{reader: reader, conn: conn}, &h1StreamWriter{conn: conn}, dispatcher)
		}

		dest, err := http_proto.ParseHost(host, 443)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return errors.New("malformed proxy host: ", host).AtWarning().Base(err)
		}
		dest.Network = xnet.Network_TCP
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     dest,
			Status: log.AccessAccepted,
			Email:  user.Email,
		})

		_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			return errors.New("failed to write back OK response").Base(err)
		}

		r := buf.NewReader(conn)
		if reader.Buffered() > 0 {
			payload, err := buf.ReadFrom(io.LimitReader(reader, int64(reader.Buffered())))
			if err != nil {
				return err
			}
			r = &buf.BufferedReader{Reader: r, Buffer: payload}
		}
		if inbound != nil && inbound.CanSpliceCopy == 2 {
			inbound.CanSpliceCopy = 1
		}
		// Single CONNECT per H1 connection for tunnels; DispatchLink relays
		// until either side closes.
		if err := dispatcher.DispatchLink(ctx, dest, &transport.Link{
			Reader: r,
			Writer: buf.NewWriter(conn),
		}); err != nil {
			return errors.New("failed to dispatch request").Base(err)
		}
		return nil
	}
}

type readerOnly struct {
	io.Reader
}

type h1StreamReader struct {
	reader *bufio.Reader
	conn   stat.Connection
}

func (r *h1StreamReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

type h1StreamWriter struct {
	conn stat.Connection
}

func (w *h1StreamWriter) Write(p []byte) (int, error) {
	return w.conn.Write(p)
}

// ─── HTTP/2 path ────────────────────────────────────────────────────────────

type h2Handler struct {
	server     *Server
	ctx        context.Context
	dispatcher routing.Dispatcher
}

func (s *Server) handleH2(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	srv := &http2.Server{}
	opts := &http2.ServeConnOpts{
		Handler: &h2Handler{server: s, ctx: ctx, dispatcher: dispatcher},
	}
	srv.ServeConn(conn, opts)
	return nil
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Method, "CONNECT") {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := h.server.authenticate(r.Header.Get("Proxy-Authorization"))
	if user == nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="trusttunnel"`)
		w.WriteHeader(407)
		return
	}

	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}

	inbound := session.InboundFromContext(h.ctx)
	if inbound != nil {
		inbound.User = user
	}

	switch pseudoHostOf(host) {
	case pseudoCheck:
		w.WriteHeader(http.StatusOK)
		return
	case pseudoICMP:
		w.WriteHeader(http.StatusNotImplemented)
		return
	case pseudoUDP:
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_ = h.server.handleUDPStream(h.ctx, user, r.Body, &flushWriter{w: w}, h.dispatcher)
		return
	}

	dest, err := http_proto.ParseHost(host, 443)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dest.Network = xnet.Network_TCP
	ctx := log.ContextWithAccessMessage(h.ctx, &log.AccessMessage{
		From:   nil,
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})

	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_ = h.dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(r.Body),
		Writer: buf.NewWriter(&flushWriter{w: w}),
	})
}

// flushWriter flushes after every write so tunneled data is sent promptly
// over the H2 stream.
type flushWriter struct {
	w http.ResponseWriter
}

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

// ─── helpers ────────────────────────────────────────────────────────────────

func (s *Server) policy() policy.Session {
	return s.policyManager.ForLevel(0)
}

// pseudoHostOf extracts the hostname part of an authority for pseudo-host
// comparison ("_udp2", "_udp2:0", "[_icmp]:0" forms included).
func pseudoHostOf(authority string) string {
	host := authority
	if h, _, err := stdnet.SplitHostPort(authority); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(strings.TrimSpace(host))
	// Strip optional :port suffix left by malformed split (e.g. "_udp2:0"
	// without brackets fails SplitHostPort? No — "_udp2:0" splits fine).
	return host
}

// addr16ToString converts a 16-byte padded address (IPv4 zero-padded per
// spec) to its string form.
func addr16ToString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	ipv4 := true
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			ipv4 = false
			break
		}
	}
	if ipv4 {
		return stdnet.IP(b[12:16]).String()
	}
	return stdnet.IP(b).String()
}

func addrTo16(s string) [16]byte {
	var out [16]byte
	ip := stdnet.ParseIP(s)
	if ip == nil {
		return out
	}
	if v4 := ip.To4(); v4 != nil {
		copy(out[12:16], v4)
		return out
	}
	copy(out[:], ip.To16())
	return out
}

// ─── UDP multiplexing (PROTOCOL.md §6) ──────────────────────────────────────

type udpPacket struct {
	srcAddr [16]byte
	srcPort uint16
	dstAddr [16]byte
	dstPort uint16
	payload []byte
}

// readUDPPacket reads one client→endpoint packet (with app-name field).
func readUDPPacket(r io.Reader) (*udpPacket, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length < 16+2+16+2+1 || length > maxUDPPacket {
		return nil, errors.New("trusttunnel: invalid udp packet length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	p := &udpPacket{}
	copy(p.srcAddr[:], body[0:16])
	p.srcPort = binary.BigEndian.Uint16(body[16:18])
	copy(p.dstAddr[:], body[18:34])
	p.dstPort = binary.BigEndian.Uint16(body[34:36])
	appLen := int(body[36])
	if 37+appLen > len(body) {
		return nil, errors.New("trusttunnel: invalid app name length")
	}
	p.payload = body[37+appLen:]
	return p, nil
}

// encodeUDPResponse encodes one endpoint→client packet (no app-name field).
func encodeUDPResponse(srcAddr [16]byte, srcPort uint16, dstAddr [16]byte, dstPort uint16, payload []byte) []byte {
	length := 16 + 2 + 16 + 2 + len(payload)
	out := make([]byte, 4+length)
	binary.BigEndian.PutUint32(out[0:4], uint32(length))
	copy(out[4:20], srcAddr[:])
	binary.BigEndian.PutUint16(out[20:22], srcPort)
	copy(out[22:38], dstAddr[:])
	binary.BigEndian.PutUint16(out[38:40], dstPort)
	copy(out[40:], payload)
	return out
}

type udpSession struct {
	link       *transport.Link
	clientAddr [16]byte
	clientPort uint16
	dstAddr    [16]byte
	dstPort    uint16
	lastActive time.Time
	cancel     context.CancelFunc
}

func (s *Server) handleUDPStream(ctx context.Context, user *protocol.MemoryUser, reader io.Reader, writer io.Writer, dispatcher routing.Dispatcher) error {
	var writeMu sync.Mutex
	var sessMu sync.Mutex
	sessions := make(map[string]*udpSession)

	removeSession := func(key string) {
		sessMu.Lock()
		if sess, ok := sessions[key]; ok {
			delete(sessions, key)
			sess.cancel()
			_ = common.Close(sess.link.Reader)
			_ = common.Close(sess.link.Writer)
		}
		sessMu.Unlock()
	}

	// Idle reaper.
	stopReap := make(chan struct{})
	defer close(stopReap)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopReap:
				return
			case <-ticker.C:
				now := time.Now()
				sessMu.Lock()
				for key, sess := range sessions {
					if now.Sub(sess.lastActive) > udpSessionTimeout {
						delete(sessions, key)
						sess.cancel()
						_ = common.Close(sess.link.Reader)
						_ = common.Close(sess.link.Writer)
					}
				}
				sessMu.Unlock()
			}
		}
	}()
	defer func() {
		sessMu.Lock()
		for _, sess := range sessions {
			sess.cancel()
			_ = common.Close(sess.link.Reader)
			_ = common.Close(sess.link.Writer)
		}
		sessMu.Unlock()
	}()

	for {
		pkt, err := readUDPPacket(reader)
		if err != nil {
			if errors.Cause(err) == io.EOF || errors.Cause(err) == io.ErrUnexpectedEOF {
				return nil
			}
			return errors.New("trusttunnel: read udp packet").Base(err)
		}

		dstStr := addr16ToString(pkt.dstAddr[:])
		if dstStr == "" {
			continue
		}
		dest := xnet.UDPDestination(xnet.ParseAddress(dstStr), xnet.Port(pkt.dstPort))
		key := dstStr + ":" + strconv.Itoa(int(pkt.dstPort))

		sessMu.Lock()
		sess, ok := sessions[key]
		if !ok {
			sctx, cancel := context.WithCancel(ctx)
			sctx = log.ContextWithAccessMessage(sctx, &log.AccessMessage{
				To:     dest,
				Status: log.AccessAccepted,
				Email:  user.Email,
			})
			link, err := dispatcher.Dispatch(sctx, dest)
			if err != nil {
				sessMu.Unlock()
				cancel()
				errors.LogInfoInner(ctx, err, "trusttunnel: dispatch udp to ", dest)
				continue
			}
			sess = &udpSession{
				link:       link,
				clientAddr: pkt.srcAddr,
				clientPort: pkt.srcPort,
				dstAddr:    pkt.dstAddr,
				dstPort:    pkt.dstPort,
				lastActive: time.Now(),
				cancel:     cancel,
			}
			sessions[key] = sess
			go s.udpSessionReader(sess, key, removeSession, &writeMu, writer)
		} else {
			sess.lastActive = time.Now()
			// Refresh client source (may change across packets).
			sess.clientAddr = pkt.srcAddr
			sess.clientPort = pkt.srcPort
		}
		link := sess.link
		sessMu.Unlock()

		b := buf.FromBytes(pkt.payload)
		b.UDP = &dest
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			removeSession(key)
			continue
		}
	}
}

func (s *Server) udpSessionReader(sess *udpSession, key string, remove func(string), writeMu *sync.Mutex, writer io.Writer) {
	defer remove(key)
	for {
		mb, err := sess.link.Reader.ReadMultiBuffer()
		if err != nil {
			return
		}
		for _, b := range mb {
			payload := append([]byte(nil), b.Bytes()...)
			var srcAddr [16]byte
			var srcPort uint16
			if b.UDP != nil && b.UDP.Address != nil {
				srcAddr = addrTo16(b.UDP.Address.String())
				srcPort = uint16(b.UDP.Port)
			} else {
				srcAddr = sess.dstAddr
				srcPort = sess.dstPort
			}
			resp := encodeUDPResponse(srcAddr, srcPort, sess.clientAddr, sess.clientPort, payload)
			b.Release()
			writeMu.Lock()
			_, werr := writer.Write(resp)
			writeMu.Unlock()
			if werr != nil {
				return
			}
			sess.lastActive = time.Now()
		}
		buf.ReleaseMulti(mb)
	}
}
