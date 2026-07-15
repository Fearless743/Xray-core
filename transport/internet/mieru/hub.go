package mieru

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/mieru/account"
	mieruCtx "github.com/xtls/xray-core/proxy/mieru/ctx"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

// Listener wraps the official mieru server API as an xray transport listener.
type Listener struct {
	server  mieruserver.Server
	addConn internet.ConnHandler
	ctx     context.Context
	cancel  context.CancelFunc
	addr    net.Addr
	closed  bool
	mu      sync.Mutex
	users   *account.Validator
}

func (l *Listener) Addr() net.Addr { return l.addr }

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	return l.server.Stop()
}

func (l *Listener) acceptLoop() {
	for {
		conn, req, err := l.server.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed || !l.server.IsRunning() {
				return
			}
			errors.LogDebug(context.Background(), "mieru accept error: ", err)
			continue
		}
		go l.handleConn(conn, req)
	}
}

func (l *Listener) handleConn(conn net.Conn, req *mierumodel.Request) {
	// SOCKS5 success response required by official protocol.
	resp := &mierumodel.Response{
		Reply: mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{
			IP:   net.IPv4zero,
			Port: 0,
		},
	}
	if err := resp.WriteToSocks5(conn); err != nil {
		_ = conn.Close()
		return
	}

	dest, err := requestToDestination(req)
	if err != nil {
		_ = conn.Close()
		return
	}

	var user *protocol.MemoryUser
	if uc, ok := conn.(mierucommon.UserContext); ok {
		if name := uc.UserName(); name != "" && l.users != nil {
			user = l.users.GetByName(name)
		}
	}

	wrapped := &InterConn{
		Conn:   conn,
		target: dest,
		user:   user,
	}
	l.addConn(wrapped)
}

// InterConn carries destination/user metadata from official mieru Accept().
type InterConn struct {
	net.Conn
	target xnet.Destination
	user   *protocol.MemoryUser
}

func (c *InterConn) Target() xnet.Destination    { return c.target }
func (c *InterConn) User() *protocol.MemoryUser  { return c.user }

func requestToDestination(req *mierumodel.Request) (xnet.Destination, error) {
	network := xnet.Network_TCP
	if req.Command == mieruconstant.Socks5UDPAssociateCmd {
		network = xnet.Network_UDP
	}
	var host string
	if req.DstAddr.FQDN != "" {
		host = req.DstAddr.FQDN
	} else if req.DstAddr.IP != nil {
		host = req.DstAddr.IP.String()
	} else {
		return xnet.Destination{}, errors.New("mieru: empty destination")
	}
	prefix := "tcp:"
	if network == xnet.Network_UDP {
		prefix = "udp:"
	}
	return xnet.ParseDestination(prefix + net.JoinHostPort(host, itoa(req.DstAddr.Port)))
}

func itoa(p int) string {
	if p <= 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}

func Listen(ctx context.Context, address xnet.Address, port xnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	validator := mieruCtx.ValidatorFromContext(ctx)
	if validator == nil {
		return nil, errors.New("mieru: validator is nil")
	}
	transport := mieruCtx.TransportFromContext(ctx)
	if transport == "" {
		if cfg, ok := streamSettings.ProtocolSettings.(*Config); ok && cfg != nil && cfg.Transport != "" {
			transport = cfg.Transport
		} else {
			transport = "TCP"
		}
	}
	trafficPattern := mieruCtx.TrafficPatternFromContext(ctx)
	if trafficPattern == "" {
		if cfg, ok := streamSettings.ProtocolSettings.(*Config); ok && cfg != nil {
			trafficPattern = cfg.TrafficPattern
		}
	}

	var tp *mierupb.TransportProtocol
	switch strings.ToUpper(transport) {
	case "UDP":
		tp = mierupb.TransportProtocol_UDP.Enum()
	default:
		tp = mierupb.TransportProtocol_TCP.Enum()
	}

	entries := validator.Entries()
	if len(entries) == 0 {
		return nil, errors.New("mieru: no users")
	}
	users := make([]*mierupb.User, 0, len(entries))
	for _, e := range entries {
		name := e.Name
		pass := e.Password
		users = append(users, &mierupb.User{
			Name:     proto.String(name),
			Password: proto.String(pass),
		})
	}

	var traffic *mierupb.TrafficPattern
	if trafficPattern != "" {
		decoded, err := mierutp.Decode(trafficPattern)
		if err != nil {
			return nil, errors.New("mieru: invalid traffic_pattern").Base(err)
		}
		if err := mierutp.Validate(decoded); err != nil {
			return nil, errors.New("mieru: invalid traffic_pattern").Base(err)
		}
		traffic = decoded
	}

	listenIP := "0.0.0.0"
	if address != nil && !address.Family().IsDomain() {
		if ip := address.IP(); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				listenIP = v4.String()
			} else {
				listenIP = ip.String()
			}
		}
	}

	// Official API binds via PortBindings; address is host:port style through listener factory.
	// Default factories listen on all interfaces for the given port.
	cfg := &mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: []*mierupb.PortBinding{
				{
					Port:     proto.Int32(int32(port)),
					Protocol: tp,
				},
			},
			Users:          users,
			TrafficPattern: traffic,
		},
	}

	// Custom listener factories so we honor listen address + socket options.
	sockopt := streamSettings.SocketSettings
	cfg.StreamListenerFactory = streamListenerFactory{ctx: ctx, sockopt: sockopt, prefer: listenIP}
	cfg.PacketListenerFactory = packetListenerFactory{ctx: ctx, sockopt: sockopt, prefer: listenIP}

	s := mieruserver.NewServer()
	if err := s.Store(cfg); err != nil {
		return nil, errors.New("mieru: store config").Base(err)
	}
	if err := s.Start(); err != nil {
		return nil, errors.New("mieru: start server").Base(err)
	}

	ctx2, cancel := context.WithCancel(ctx)
	l := &Listener{
		server:  s,
		addConn: handler,
		ctx:     ctx2,
		cancel:  cancel,
		users:   validator,
		addr:    &net.TCPAddr{IP: net.ParseIP(listenIP), Port: int(port)},
	}
	// Give server a moment to bind.
	time.Sleep(20 * time.Millisecond)
	go l.acceptLoop()
	return l, nil
}

type streamListenerFactory struct {
	ctx    context.Context
	sockopt *internet.SocketConfig
	prefer string
}

func (f streamListenerFactory) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// address is typically ":port" from official code; force preferred IP if set.
	host, port, err := net.SplitHostPort(address)
	if err == nil && (host == "" || host == "0.0.0.0" || host == "::") && f.prefer != "" {
		address = net.JoinHostPort(f.prefer, port)
	}
	var addr net.Addr
	switch network {
	case "tcp", "tcp4", "tcp6":
		a, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		addr = a
	default:
		return net.Listen(network, address)
	}
	return internet.ListenSystem(f.ctx, addr, f.sockopt)
}

type packetListenerFactory struct {
	ctx    context.Context
	sockopt *internet.SocketConfig
	prefer string
}

func (f packetListenerFactory) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err == nil && (host == "" || host == "0.0.0.0" || host == "::") && f.prefer != "" {
		address = net.JoinHostPort(f.prefer, port)
	}
	var addr net.Addr
	switch network {
	case "udp", "udp4", "udp6":
		a, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		addr = a
	default:
		return net.ListenPacket(network, address)
	}
	return internet.ListenSystemPacket(f.ctx, addr, f.sockopt)
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
