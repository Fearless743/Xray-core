package masque

import (
	"bufio"
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/masque/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	defaultMTU        = 1280
	udpSessionTimeout = 120 * time.Second
	maxDatagramPacket = 65535
	inboundName       = "masque"
)

// tunnelConn is implemented by transport/internet/masque.Conn (structural).
type tunnelConn interface {
	stat.Connection
	Credentials() (username, password string)
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
	statsManager  stats.Manager
	ctx           context.Context

	pools       []*addressPool
	serverAddrs []netip.Addr
	advertised  []AddressRange
	ipstack     *ipStack
	mtu         uint32

	dispatcher atomic.Pointer[routing.Dispatcher]

	sessMu   sync.RWMutex
	sessions map[netip.Addr]*masqueSession
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
			return nil, errors.New("failed to get masque user").Base(err).AtError()
		}
		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}
	if len(config.Addresses) == 0 {
		return nil, errors.New("masque: at least one tunnel address is required")
	}
	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		statsManager:  v.GetFeature(stats.ManagerType()).(stats.Manager),
		ctx:           ctx,
		sessions:      make(map[netip.Addr]*masqueSession),
		mtu:           config.Mtu,
	}
	if s.mtu == 0 {
		s.mtu = defaultMTU
	}
	seenV4, seenV6 := false, false
	for _, a := range config.Addresses {
		prefix, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, errors.New("masque: invalid tunnel address ", a).Base(err)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4() {
			if seenV4 {
				return nil, errors.New("masque: multiple IPv4 tunnel addresses are not supported")
			}
			seenV4 = true
		} else {
			if seenV6 {
				return nil, errors.New("masque: multiple IPv6 tunnel addresses are not supported")
			}
			seenV6 = true
		}
		s.serverAddrs = append(s.serverAddrs, prefix.Addr())
		s.pools = append(s.pools, newAddressPool(prefix))
	}
	// Probe pools: each must leave at least one assignable address.
	for i, pool := range s.pools {
		addr, ok := pool.allocate()
		if !ok {
			return nil, errors.New("masque: tunnel prefix leaves no addresses to assign")
		}
		pool.release(addr)
		_ = i
	}
	if len(config.AdvertiseRoutes) == 0 {
		s.advertised = []AddressRange{
			{Start: netip.IPv4Unspecified(), End: netip.AddrFrom4([4]byte{255, 255, 255, 255})},
			{Start: netip.IPv6Unspecified(), End: netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})},
		}
	} else {
		for _, r := range config.AdvertiseRoutes {
			prefix, err := netip.ParsePrefix(r)
			if err != nil {
				if addr, err2 := netip.ParseAddr(r); err2 == nil {
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				} else {
					return nil, errors.New("masque: invalid advertise route ", r).Base(err)
				}
			}
			prefix = prefix.Masked()
			s.advertised = append(s.advertised, AddressRange{
				Start: prefix.Addr(),
				End:   lastAddr(prefix),
			})
		}
	}
	ipstack, err := newIPStack(s.mtu, s.serverAddrs, s.handleTCPForward)
	if err != nil {
		return nil, err
	}
	s.ipstack = ipstack
	go s.drainStack()
	return s, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	bits := addr.BitLen() - p.Bits()
	if addr.Is4() {
		a := addr.As4()
		v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		v |= (1 << bits) - 1
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	a := addr.As16()
	hi := uint64(a[0])<<56 | uint64(a[1])<<48 | uint64(a[2])<<40 | uint64(a[3])<<32 | uint64(a[4])<<24 | uint64(a[5])<<16 | uint64(a[6])<<8 | uint64(a[7])
	lo := uint64(a[8])<<56 | uint64(a[9])<<48 | uint64(a[10])<<40 | uint64(a[11])<<32 | uint64(a[12])<<24 | uint64(a[13])<<16 | uint64(a[14])<<8 | uint64(a[15])
	if bits >= 64 {
		lo |= (uint64(1) << (bits - 64)) - 1
		hi = ^uint64(0)
		if bits == 64 {
			lo = ^uint64(0)
		}
	} else {
		lo |= (uint64(1) << bits) - 1
	}
	var out [16]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(hi >> (56 - 8*i))
		out[8+i] = byte(lo >> (56 - 8*i))
	}
	return netip.AddrFrom16(out)
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// MasqueInboundValidator exposes the user table to the transport layer.
func (s *Server) MasqueInboundValidator() *account.Validator { return s.validator }

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

// ─── session ────────────────────────────────────────────────────────────────

type masqueSession struct {
	server     *Server
	conn       tunnelConn
	user       *protocol.MemoryUser
	email      string
	addrs      []netip.Addr
	peerRoutes []AddressRange

	ctx    context.Context
	cancel context.CancelCauseFunc

	upCounter   stats.Counter
	downCounter stats.Counter

	// dnat maps (client addr, client port, original dst port) to the original
	// destination IP for TCP connections whose destination was rewritten to
	// a server address (see handlePacket). Session-scoped: dropped on close.
	natMu sync.Mutex
	nat   map[natKey]netip.Addr

	udpMu       sync.Mutex
	udpSessions map[udpKey]*udpSession
}

type natKey struct {
	src   netip.Addr
	sport uint16
	dport uint16
}

type udpKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

type udpSession struct {
	link       *transport.Link
	lastActive time.Time
	cancel     context.CancelFunc
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = inboundName
		inbound.CanSpliceCopy = 3
	}
	d := dispatcher
	s.dispatcher.Store(&d)

	tconn, ok := stat.TryUnwrapStatsConn(conn).(tunnelConn)
	if !ok {
		return errors.New("masque: unsupported connection type")
	}
	_, password := tconn.Credentials()
	user := s.validator.GetByPassword(password)
	if user == nil {
		_ = tconn.Close()
		return errors.New("masque: invalid user")
	}
	if inbound != nil {
		inbound.User = user
	}

	sessCtx, cancel := context.WithCancelCause(ctx)
	sess := &masqueSession{
		server:      s,
		conn:        tconn,
		user:        user,
		email:       user.Email,
		ctx:         sessCtx,
		cancel:      cancel,
		nat:         make(map[natKey]netip.Addr),
		udpSessions: make(map[udpKey]*udpSession),
	}
	if s.statsManager != nil {
		sess.upCounter, _ = stats.GetOrRegisterCounter(s.statsManager, "user>>>"+user.Email+">>>traffic>>>uplink")
		sess.downCounter, _ = stats.GetOrRegisterCounter(s.statsManager, "user>>>"+user.Email+">>>traffic>>>downlink")
	}

	// Allocate one address per pool.
	for _, pool := range s.pools {
		addr, allocated := pool.allocate()
		if !allocated {
			s.releaseAddrs(sess)
			_ = tconn.Close()
			return errors.New("masque: address pool exhausted")
		}
		sess.addrs = append(sess.addrs, addr)
	}
	s.sessMu.Lock()
	for _, addr := range sess.addrs {
		s.sessions[addr] = sess
	}
	s.sessMu.Unlock()

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     addrsToDestination(sess.addrs),
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "masque: inbound tunnel assigned [", addrsString(sess.addrs), "]")

	// Unsolicited ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT (sing-box behavior).
	if err := sess.writeBytes(encodeAddressCapsule(capsuleTypeAddressAssign, sess.assignedAddresses(nil))); err != nil {
		s.closeSession(sess)
		return err
	}
	if err := sess.writeBytes(encodeRouteCapsule(s.advertised)); err != nil {
		s.closeSession(sess)
		return err
	}

	go sess.readDatagrams()
	err := sess.readCapsules()
	s.closeSession(sess)
	if err != nil && !isClosedErr(err) {
		return errors.New("masque: tunnel closed").Base(err)
	}
	return nil
}

func (s *Server) releaseAddrs(sess *masqueSession) {
	for _, addr := range sess.addrs {
		for _, pool := range s.pools {
			if pool.contains(addr) {
				pool.release(addr)
			}
		}
	}
}

func (s *Server) closeSession(sess *masqueSession) {
	sess.cancel(context.Canceled)
	s.sessMu.Lock()
	for _, addr := range sess.addrs {
		if s.sessions[addr] == sess {
			delete(s.sessions, addr)
		}
	}
	s.sessMu.Unlock()
	s.releaseAddrs(sess)
	sess.udpMu.Lock()
	for _, u := range sess.udpSessions {
		u.cancel()
		common.Close(u.link.Reader)
		common.Close(u.link.Writer)
	}
	sess.udpSessions = make(map[udpKey]*udpSession)
	sess.udpMu.Unlock()
	_ = sess.conn.Close()
}

func (s *Server) findSession(addr netip.Addr) *masqueSession {
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	return s.sessions[addr]
}

func (s *Server) isServerAddr(addr netip.Addr) bool {
	for _, a := range s.serverAddrs {
		if a == addr {
			return true
		}
	}
	return false
}

func (sess *masqueSession) writeBytes(b []byte) error {
	_, err := sess.conn.Write(b)
	if err == nil {
		sess.countDown(int64(len(b)))
	}
	return err
}

func (sess *masqueSession) sendPacket(pkt []byte) error {
	err := sess.conn.SendDatagram(prependContextZero(pkt))
	if err == nil {
		sess.countDown(int64(len(pkt)))
	}
	return err
}

func (sess *masqueSession) countUp(n int64) {
	if sess.upCounter != nil {
		sess.upCounter.Add(n)
	}
}

func (sess *masqueSession) countDown(n int64) {
	if sess.downCounter != nil {
		sess.downCounter.Add(n)
	}
}

// ─── capsule + datagram loops ───────────────────────────────────────────────

func (sess *masqueSession) readCapsules() error {
	reader := bufio.NewReader(sess.conn)
	for {
		cap, err := readCapsule(reader)
		if err != nil {
			errors.LogDebug(sess.ctx, "masque: capsule stream ended: ", err)
			return err
		}
		errors.LogDebug(sess.ctx, "masque: capsule type=", cap.typ, " len=", len(cap.payload))
		switch cap.typ {
		case capsuleTypeAddressRequest:
			addrs, err := parseAddrEntries(cap.payload)
			if err != nil {
				return err
			}
			if len(addrs) == 0 {
				return errors.New("masque: empty ADDRESS_REQUEST")
			}
			reply := encodeAddressCapsule(capsuleTypeAddressAssign, sess.assignedAddresses(addrs))
			errors.LogDebug(sess.ctx, "masque: replying ASSIGN len=", len(reply))
			if err := sess.writeBytes(reply); err != nil {
				errors.LogDebug(sess.ctx, "masque: ASSIGN reply failed: ", err)
				return err
			}
			errors.LogDebug(sess.ctx, "masque: ASSIGN reply sent")
		case capsuleTypeRouteAdvertisement:
			routes, err := parseRouteEntries(cap.payload)
			if err != nil {
				return err
			}
			sess.peerRoutes = routes
			errors.LogInfo(sess.ctx, "masque: peer advertised ", len(routes), " routes")
		case capsuleTypeDatagram:
			pkt, ok := stripContextZero(cap.payload)
			if !ok {
				continue
			}
			sess.handlePacket(append([]byte(nil), pkt...))
		default:
			// Ignore unknown capsules (forward compatibility).
		}
	}
}

func (sess *masqueSession) readDatagrams() {
	defer sess.cancel(context.Canceled)
	for {
		dgram, err := sess.conn.ReceiveDatagram(sess.ctx)
		if err != nil {
			errors.LogDebug(sess.ctx, "masque: datagram recv ended: ", err)
			return
		}
		errors.LogDebug(sess.ctx, "masque: datagram received len=", len(dgram))
		pkt, ok := stripContextZero(dgram)
		if !ok {
			continue
		}
		sess.countUp(int64(len(pkt)))
		sess.handlePacket(append([]byte(nil), pkt...))
	}
}

// assignedAddresses mirrors sing-box behavior: answer each request with a
// same-family address (or unspecified when unavailable), then list the rest.
func (sess *masqueSession) assignedAddresses(requests []AssignedAddress) []AssignedAddress {
	answered := make(map[netip.Addr]bool)
	var out []AssignedAddress
	for _, req := range requests {
		var found netip.Addr
		for _, addr := range sess.addrs {
			if answered[addr] {
				continue
			}
			if addr.Is4() == req.Prefix.Addr().Is4() {
				found = addr
				break
			}
		}
		if !found.IsValid() {
			unspecified := netip.IPv4Unspecified()
			if req.Prefix.Addr().Is6() {
				unspecified = netip.IPv6Unspecified()
			}
			out = append(out, AssignedAddress{RequestID: req.RequestID, Prefix: netip.PrefixFrom(unspecified, unspecified.BitLen())})
			continue
		}
		answered[found] = true
		out = append(out, AssignedAddress{RequestID: req.RequestID, Prefix: netip.PrefixFrom(found, found.BitLen())})
	}
	for _, addr := range sess.addrs {
		if !answered[addr] {
			out = append(out, AssignedAddress{Prefix: netip.PrefixFrom(addr, addr.BitLen())})
		}
	}
	return out
}

// handlePacket validates and routes one client→server IP packet.
func (sess *masqueSession) handlePacket(pkt []byte) {
	src, dst, proto, valid := parseIPPacket(pkt)
	errors.LogDebug(sess.ctx, "masque: packet src=", src, " dst=", dst, " proto=", proto, " valid=", valid)
	if !valid {
		return
	}
	if !sess.owns(src) {
		return // spoofed source
	}
	if !decrementHopLimit(pkt) {
		return // expired; MVP drops instead of ICMP time-exceeded
	}
	if proto == 17 {
		sess.handleUDP(pkt)
		return
	}
	if proto != 6 {
		if (proto == 1 || proto == 58) && !sess.server.isServerAddr(dst) {
			return // only the server answers ping; forwarding ping needs raw sockets
		}
		if sess.server.findSession(dst) != nil {
			return // no client-to-client relay in MVP
		}
		// Non-TCP: terminate in netstack (exact-local delivery only).
		sess.server.ipstack.inject(pkt)
		return
	}
	// TCP: the netstack only delivers exact-local destinations to the
	// forwarder, so rewrite non-local destinations to a server address
	// (DNAT) and restore them on dispatch / return path.
	if sess.server.findSession(dst) != nil {
		return // no client-to-client relay in MVP
	}
	if !sess.server.isServerAddr(dst) {
		srv := sess.serverAddrFor(dst)
		if !srv.IsValid() {
			return
		}
		if !sess.noteNAT(pkt, dst) {
			return // not a SYN and no mapping: cannot route return traffic
		}
		if !rewriteIPDst(pkt, srv) {
			return
		}
	}
	sess.server.ipstack.inject(pkt)
}

// serverAddrFor returns a server address of the same family as dst.
func (sess *masqueSession) serverAddrFor(dst netip.Addr) netip.Addr {
	for _, a := range sess.server.serverAddrs {
		if a.Is4() == dst.Is4() {
			return a
		}
	}
	return netip.Addr{}
}

// noteNAT records (or refreshes) the DNAT mapping for a TCP packet.
// Mappings are only created from SYN packets so retransmitted data cannot
// clobber the return path of an unrelated reused tuple.
func (sess *masqueSession) noteNAT(pkt []byte, origDst netip.Addr) bool {
	src, _, _, ok := parseIPPacket(pkt)
	if !ok {
		return false
	}
	sport, dport, isSYN := tcpPortsAndSYN(pkt)
	if !isSYN {
		sess.natMu.Lock()
		_, ok := sess.nat[natKey{src: src, sport: sport, dport: dport}]
		sess.natMu.Unlock()
		return ok
	}
	sess.natMu.Lock()
	sess.nat[natKey{src: src, sport: sport, dport: dport}] = origDst
	sess.natMu.Unlock()
	return true
}

func (sess *masqueSession) lookupNAT(src netip.Addr, sport, dport uint16) (netip.Addr, bool) {
	sess.natMu.Lock()
	defer sess.natMu.Unlock()
	orig, ok := sess.nat[natKey{src: src, sport: sport, dport: dport}]
	return orig, ok
}

func (sess *masqueSession) owns(addr netip.Addr) bool {
	for _, a := range sess.addrs {
		if a == addr {
			return true
		}
	}
	return false
}

// ─── stack outbound drain ───────────────────────────────────────────────────

func (s *Server) drainStack() {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		raw := s.ipstack.readOutbound(ctx)
		if len(raw) == 0 {
			return
		}
		if err := ctx.Err(); err != nil {
			return
		}
		src, dst, proto, valid := parseIPPacket(raw)
		if !valid || proto != 6 {
			continue
		}
		sess := s.findSession(dst)
		if sess == nil {
			continue
		}
		// Un-DNAT: packets emitted by the stack carry the server address
		// as source; restore the real origin when a mapping exists.
		if s.isServerAddr(src) {
			sport, dport := tcpPorts(raw)
			if orig, ok := sess.lookupNAT(dst, dport, sport); ok {
				if !rewriteIPSrc(raw, orig) {
					continue
				}
			}
		}
		_ = sess.sendPacket(raw)
	}
}

// ─── TCP forward (netstack → Xray dispatcher) ───────────────────────────────

func (s *Server) handleTCPForward(r *tcp.ForwarderRequest) {
	id := r.ID()
	srcAddr, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstAddr, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	errors.LogDebug(context.Background(), "masque: TCP forward request src=", srcAddr, " dst=", dstAddr, ":", id.LocalPort)
	sess := s.findSession(srcAddr)
	if sess == nil {
		r.Complete(true)
		return
	}
	// Restore the original destination for DNAT-rewritten connections.
	origDst := dstAddr
	if mapped, ok := sess.lookupNAT(srcAddr, id.RemotePort, id.LocalPort); ok {
		origDst = mapped
	}
	dst := xnet.TCPDestination(xnet.ParseAddress(origDst.String()), xnet.Port(id.LocalPort))
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	tcpConn := gonet.NewTCPConn(&wq, ep)
	defer tcpConn.Close()

	dispatcher := s.dispatcher.Load()
	if dispatcher == nil {
		return
	}
	ctx := log.ContextWithAccessMessage(sess.ctx, &log.AccessMessage{
		From:   xnet.TCPDestination(xnet.ParseAddress(srcAddr.String()), xnet.Port(id.RemotePort)),
		To:     dst,
		Status: log.AccessAccepted,
		Email:  sess.email,
	})
	link, err := (*dispatcher).Dispatch(ctx, dst)
	if err != nil {
		errors.LogInfoInner(ctx, err, "masque: dispatch TCP to ", dst)
		return
	}
	errors.LogInfo(ctx, "masque: tunneling TCP to ", dst)
	done := make(chan struct{}, 2)
	cc := &countConn{Conn: tcpConn, onRead: sess.countUp, onWrite: sess.countDown}
	go func() {
		_ = buf.Copy(buf.NewReader(cc), link.Writer)
		done <- struct{}{}
	}()
	go func() {
		_ = buf.Copy(link.Reader, buf.NewWriter(cc))
		done <- struct{}{}
	}()
	<-done
	_ = tcpConn.Close()
	<-done
}

// ─── UDP manual path ────────────────────────────────────────────────────────

func (sess *masqueSession) handleUDP(pkt []byte) {
	srcIP, dstIP, _, valid := parseIPPacket(pkt)
	if !valid {
		return
	}
	isV4 := ipVersion(pkt) == 4
	var udpOff int
	if isV4 {
		udpOff = int(pkt[0]&0x0F) * 4
	} else {
		udpOff = 40
	}
	if len(pkt) < udpOff+8 {
		return
	}
	srcPort := uint16(pkt[udpOff])<<8 | uint16(pkt[udpOff+1])
	dstPort := uint16(pkt[udpOff+2])<<8 | uint16(pkt[udpOff+3])
	payload := append([]byte(nil), pkt[udpOff+8:]...)

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)
	key := udpKey{src: src, dst: dst}

	dispatcher := sess.server.dispatcher.Load()
	if dispatcher == nil {
		return
	}
	sess.udpMu.Lock()
	usess, ok := sess.udpSessions[key]
	if !ok {
		dest := xnet.UDPDestination(xnet.ParseAddress(dstIP.String()), xnet.Port(dstPort))
		ctx, cancel := context.WithCancel(sess.ctx)
		link, err := (*dispatcher).Dispatch(ctx, dest)
		if err != nil {
			sess.udpMu.Unlock()
			cancel()
			errors.LogInfoInner(sess.ctx, err, "masque: dispatch UDP to ", dest)
			return
		}
		usess = &udpSession{link: link, lastActive: time.Now(), cancel: cancel}
		sess.udpSessions[key] = usess
		go sess.udpReader(usess, key, src, isV4)
	} else {
		usess.lastActive = time.Now()
	}
	link := usess.link
	sess.udpMu.Unlock()

	b := buf.FromBytes(payload)
	udpDest := xnet.UDPDestination(xnet.ParseAddress(dstIP.String()), xnet.Port(dstPort))
	b.UDP = &udpDest
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		sess.removeUDPSession(key)
	}
}

func (sess *masqueSession) udpReader(usess *udpSession, key udpKey, src netip.AddrPort, isV4 bool) {
	defer sess.removeUDPSession(key)
	for {
		mb, err := usess.link.Reader.ReadMultiBuffer()
		if err != nil {
			return
		}
		for _, b := range mb {
			payload := append([]byte(nil), b.Bytes()...)
			var rsrc netip.Addr
			var rport uint16
			if b.UDP != nil && b.UDP.Address != nil {
				rsrc, _ = netip.ParseAddr(b.UDP.Address.String())
				rport = uint16(b.UDP.Port)
			} else {
				rsrc, rport = key.dst.Addr(), key.dst.Port()
			}
			b.Release()
			var resp []byte
			if isV4 {
				resp = buildIPv4UDP(key.dst.Addr(), rsrc, key.dst.Port(), rport, payload)
			} else {
				resp = buildIPv6UDP(key.dst.Addr(), rsrc, key.dst.Port(), rport, payload)
			}
			if resp == nil {
				continue
			}
			usess.lastActive = time.Now()
			if err := sess.sendPacket(resp); err != nil {
				return
			}
			_ = src
		}
		buf.ReleaseMulti(mb)
	}
}

func (sess *masqueSession) removeUDPSession(key udpKey) {
	sess.udpMu.Lock()
	if usess, ok := sess.udpSessions[key]; ok {
		delete(sess.udpSessions, key)
		usess.cancel()
		common.Close(usess.link.Reader)
		common.Close(usess.link.Writer)
	}
	sess.udpMu.Unlock()
}

// ─── helpers ────────────────────────────────────────────────────────────────

func addrsString(addrs []netip.Addr) string {
	out := ""
	for i, a := range addrs {
		if i > 0 {
			out += ","
		}
		out += a.String()
	}
	return out
}

func addrsToDestination(addrs []netip.Addr) xnet.Destination {
	if len(addrs) == 0 {
		return xnet.Destination{}
	}
	return xnet.UDPDestination(xnet.ParseAddress(addrs[0].String()), 0)
}

func isClosedErr(err error) bool {
	if err == nil {
		return true
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF || err == io.ErrClosedPipe || err == context.Canceled {
		return true
	}
	return false
}

// countConn attributes tunnel bytes to per-user traffic counters.
type countConn struct {
	stdnet.Conn
	onRead  func(int64)
	onWrite func(int64)
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.onRead != nil {
		c.onRead(int64(n))
	}
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.onWrite != nil {
		c.onWrite(int64(n))
	}
	return n, err
}
