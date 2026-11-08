package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
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

// Extended-CONNECT sub-protocols served on one QUIC listener.
const (
	protoConnectIP   = "connect-ip"    // sing-box: Basic auth, server-assigned addresses
	protoUsqueIP     = "cf-connect-ip" // usque/mihomo: ECDSA device key, static addresses
)

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

// parseEndpointKey accepts a PEM (SEC1 "EC PRIVATE KEY" or PKCS#8) or raw
// base64 DER encoding of an ECDSA P-256 private key.
func parseEndpointKey(s string) (*ecdsa.PrivateKey, error) {
	raw := strings.TrimSpace(s)
	if strings.Contains(raw, "-----BEGIN") {
		return parsePEMECKey(raw)
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if der, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			return nil, errors.New("masque: invalid endpoint key encoding").Base(err)
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if k8, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if key, ok := k8.(*ecdsa.PrivateKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("masque: invalid endpoint key DER")
}

func parsePEMECKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("masque: no PEM block in endpoint key")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if key, ok := k.(*ecdsa.PrivateKey); ok {
			return key, nil
		}
		return nil, errors.New("masque: endpoint key is not ECDSA")
	default:
		return nil, errors.New("masque: unsupported PEM type " + block.Type)
	}
}

// selfSignedCert builds a long-lived self-signed TLS certificate from the
// endpoint key. Clients pin the endpoint public key (usque) or skip
// verification (sing-box), so rotation is transparent.
func selfSignedCert(key *ecdsa.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Fboard MASQUE"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, nil
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
	keyPEM := strings.TrimSpace(config.EndpointKey)
	if keyPEM == "" {
		// Back-compat: legacy certificate/key pair (sing-box-only deployments).
		if strings.TrimSpace(config.Certificate) != "" && strings.TrimSpace(config.Key) != "" {
			cert, err := tls.X509KeyPair([]byte(config.Certificate), []byte(config.Key))
			if err != nil {
				return nil, errors.New("masque: invalid legacy TLS certificate").Base(err)
			}
			return listenWithCert(ctx, address, port, streamSettings, handler, path, validator, cert, nil)
		}
		return nil, errors.New("masque: endpoint_key is required")
	}
	ecKey, err := parseEndpointKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, errors.New("masque: endpoint key must be ECDSA P-256")
	}
	cert, err := selfSignedCert(ecKey)
	if err != nil {
		return nil, errors.New("masque: failed to build server certificate").Base(err)
	}
	return listenWithCert(ctx, address, port, streamSettings, handler, path, validator, cert, ecKey)
}

func listenWithCert(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler, path string, validator *account.Validator, cert tls.Certificate, _ *ecdsa.PrivateKey) (internet.Listener, error) {
	raw, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}
	maxIdle := 60 * time.Second
	if config, _ := streamSettings.ProtocolSettings.(*Config); config != nil && config.MaxIdleTimeoutMs > 0 {
		maxIdle = time.Duration(config.MaxIdleTimeoutMs) * time.Millisecond
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		// Request (not require) client certificates: usque/mihomo clients
		// present their device certificate, sing-box clients present none.
		// Authorization happens per-request in the handler.
		ClientAuth: tls.RequestClientCert,
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
		Handler:        http.HandlerFunc(l.handleTunnel),
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

// devicePubKeyDER extracts the ECDSA P-256 public key (PKIX DER) from the
// peer certificates presented during the QUIC handshake.
func devicePubKeyDER(r *http.Request) ([]byte, bool) {
	if r.TLS == nil {
		return nil, false
	}
	for _, cert := range r.TLS.PeerCertificates {
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && pub.Curve == elliptic.P256() {
			der, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				continue
			}
			return der, true
		}
	}
	return nil, false
}

func (l *Listener) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Method, http.MethodConnect) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch r.Proto {
	case protoConnectIP:
		l.handleSingBox(w, r)
	case protoUsqueIP:
		l.handleUsque(w, r)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (l *Listener) hijack(w http.ResponseWriter) (*http3.Stream, bool) {
	hijacker, ok := w.(interface {
		HTTPStream() *http3.Stream
	})
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, false
	}
	w.WriteHeader(http.StatusOK)
	return hijacker.HTTPStream(), true
}

func (l *Listener) remoteAddr(r *http.Request) net.Addr {
	remote := l.pktConn.LocalAddr()
	if r.RemoteAddr != "" {
		if addr, err := net.ResolveUDPAddr("udp", r.RemoteAddr); err == nil {
			remote = addr
		}
	}
	return remote
}

// handleSingBox serves sing-box CONNECT-IP clients (Basic auth, path prefix).
func (l *Listener) handleSingBox(w http.ResponseWriter, r *http.Request) {
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
	stream, ok := l.hijack(w)
	if !ok {
		return
	}
	l.addConn(&Conn{
		stream:   stream,
		local:    l.qListener.Addr(),
		remote:   l.remoteAddr(r),
		username: username,
		password: password,
	})
}

// handleUsque serves usque/mihomo clients (ECDSA device certificate, any path).
// The request URI defaults to https://cloudflareaccess.com (path "/") and any
// path is accepted: the tunnel carries raw IP packets either way.
func (l *Listener) handleUsque(w http.ResponseWriter, r *http.Request) {
	der, ok := devicePubKeyDER(r)
	if !ok || l.validator.GetByPassword(base64.StdEncoding.EncodeToString(der)) == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="masque"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	stream, ok := l.hijack(w)
	if !ok {
		return
	}
	errors.LogInfo(r.Context(), "masque: inbound usque tunnel from ", l.remoteAddr(r))
	l.addConn(&Conn{
		stream:    stream,
		local:     l.qListener.Addr(),
		remote:    l.remoteAddr(r),
		deviceKey: der,
	})
}
