package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/masque/account"
	masqueCtx "github.com/xtls/xray-core/proxy/masque/ctx"
	"github.com/xtls/xray-core/transport/internet"
)

const defaultPath = "/.well-known/masque/ip/"

type Listener struct {
	ctx       context.Context
	pktConn   net.PacketConn
	qListener *quic.EarlyListener
	h3server  *http3.Server
	addConn   internet.ConnHandler
	path      string
	validator *account.Validator
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}

func Listen(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("masque: domain address is not allowed for listening")
	}
	validator := masqueCtx.ValidatorFromContext(ctx)
	if validator == nil {
		return nil, errors.New("masque: validator is nil")
	}
	config, _ := streamSettings.ProtocolSettings.(*Config)
	if config == nil {
		config = &Config{}
	}
	path := strings.TrimSpace(config.Path)
	if path == "" {
		path = defaultPath
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if strings.TrimSpace(config.Certificate) == "" || strings.TrimSpace(config.Key) == "" {
		return nil, errors.New("masque: TLS certificate and key are required")
	}
	cert, err := tls.X509KeyPair([]byte(config.Certificate), []byte(config.Key))
	if err != nil {
		return nil, errors.New("masque: invalid TLS certificate").Base(err)
	}
	raw, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}
	maxIdle := 60 * time.Second
	if config.MaxIdleTimeoutMs > 0 {
		maxIdle = time.Duration(config.MaxIdleTimeoutMs) * time.Millisecond
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 maxIdle,
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          100,
		EnableDatagrams:                true,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     512 * 1024,
		InitialConnectionReceiveWindow: 2 * 1024 * 1024,
	}
	qListener, err := quic.ListenEarly(raw, tlsConfig, quicConfig)
	if err != nil {
		_ = raw.Close()
		return nil, errors.New("masque: QUIC listen failed").Base(err)
	}
	l := &Listener{
		ctx:       ctx,
		pktConn:   raw,
		qListener: qListener,
		path:      path,
		addConn:   handler,
		validator: validator,
	}
	l.h3server = &http3.Server{
		Handler:         http.HandlerFunc(l.handleTunnel),
		EnableDatagrams: true,
	}
	go func() {
		if err := l.h3server.ServeListener(l.qListener); err != nil {
			errors.LogInfoInner(context.Background(), err, "masque: HTTP/3 server closed")
		}
	}()
	return l, nil
}

func (l *Listener) Addr() net.Addr { return l.qListener.Addr() }

func (l *Listener) Close() error {
	_ = l.h3server.Close()
	_ = l.qListener.Close()
	return l.pktConn.Close()
}

func (l *Listener) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Method, http.MethodConnect) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// quic-go exposes the :protocol pseudo-header as Request.Proto.
	if r.Proto != "connect-ip" {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	if !strings.HasPrefix(r.URL.Path, l.path) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	username, password, ok := r.BasicAuth()
	if !ok || password == "" || l.validator.GetByPassword(password) == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="masque"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hijacker, ok := w.(interface {
		HTTPStream() *http3.Stream
	})
	if !ok {
		errors.LogInfoInner(r.Context(), errors.New("hijack not supported"), "masque: cannot hijack stream")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	stream := hijacker.HTTPStream()
	remote := l.pktConn.LocalAddr()
	if r.RemoteAddr != "" {
		if addr, err := net.ResolveUDPAddr("udp", r.RemoteAddr); err == nil {
			remote = addr
		}
	}
	errors.LogInfo(r.Context(), "masque: inbound tunnel from ", remote, " user ", username)
	l.addConn(&Conn{
		stream:   stream,
		local:    l.qListener.Addr(),
		remote:   remote,
		username: username,
		password: password,
	})
}
