package masque

import (
	"bufio"
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/masque/account"
	"github.com/xtls/xray-core/transport"
)

// fakeConn implements tunnelConn in-memory for proxy-layer integration tests.
type fakeConn struct {
	streamR *io.PipeReader
	streamW *io.PipeWriter
	peerR   *io.PipeReader
	peerW   *io.PipeWriter

	dgramToServer chan []byte
	dgramToClient chan []byte
	username      string
	password      string
	closed        chan struct{}
	closeOnce     sync.Once
	local, remote stdnet.Addr
}

func newFakeConn(user, pass string) *fakeConn {
	sr, pw := io.Pipe()
	pr, sw := io.Pipe()
	return &fakeConn{
		streamR: sr, streamW: sw, peerR: pr, peerW: pw,
		dgramToServer: make(chan []byte, 128),
		dgramToClient: make(chan []byte, 128),
		username:      user, password: pass,
		closed: make(chan struct{}),
		local:  &stdnet.TCPAddr{IP: stdnet.ParseIP("127.0.0.1")},
		remote: &stdnet.TCPAddr{IP: stdnet.ParseIP("127.0.0.1")},
	}
}

func (f *fakeConn) Credentials() (string, string) { return f.username, f.password }
func (f *fakeConn) SendDatagram(b []byte) error {
	select {
	case f.dgramToClient <- append([]byte(nil), b...):
		return nil
	case <-f.closed:
		return io.ErrClosedPipe
	}
}
func (f *fakeConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-f.dgramToServer:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.closed:
		return nil, io.ErrClosedPipe
	}
}
func (f *fakeConn) Read(b []byte) (int, error)  { return f.streamR.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error) { return f.streamW.Write(b) }
func (f *fakeConn) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		_ = f.streamR.Close()
		_ = f.streamW.Close()
	})
	return nil
}
func (f *fakeConn) LocalAddr() stdnet.Addr             { return f.local }
func (f *fakeConn) RemoteAddr() stdnet.Addr            { return f.remote }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// fakeDispatcher dials loopback echo servers.
type fakeDispatcher struct {
	lastTCP xnet.Destination
}

func (f *fakeDispatcher) Type() interface{} { return routing.DispatcherType() }

func (f *fakeDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	switch dest.Network {
	case xnet.Network_TCP:
		f.lastTCP = dest
		c, err := stdnet.Dial("tcp", "127.0.0.1:12399")
		if err != nil {
			return nil, err
		}
		return &transport.Link{Reader: buf.NewReader(c), Writer: buf.NewWriter(c)}, nil
	case xnet.Network_UDP:
		c, err := stdnet.Dial("udp", "127.0.0.1:12398")
		if err != nil {
			return nil, err
		}
		return &transport.Link{Reader: &udpBufReader{conn: c.(*stdnet.UDPConn)}, Writer: &udpBufWriter{conn: c.(*stdnet.UDPConn)}}, nil
	}
	return nil, io.ErrUnexpectedEOF
}

func (f *fakeDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

func (f *fakeDispatcher) Start() error { return nil }
func (f *fakeDispatcher) Close() error { return nil }

type udpBufReader struct {
	conn *stdnet.UDPConn
}

func (r *udpBufReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	tmp := make([]byte, 65535)
	_ = r.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err := r.conn.ReadFromUDP(tmp)
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buf.FromBytes(append([]byte(nil), tmp[:n]...))}, nil
}
func (r *udpBufReader) Close() error { return r.conn.Close() }
func (r *udpBufReader) Interrupt()   {}

type udpBufWriter struct {
	conn *stdnet.UDPConn
}

func (w *udpBufWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if _, err := w.conn.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
func (w *udpBufWriter) Close() error { return w.conn.Close() }

func startTCPEcho(t *testing.T) {
	t.Helper()
	ln, err := stdnet.Listen("tcp", "127.0.0.1:12399")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

func startUDPEcho(t *testing.T) {
	t.Helper()
	pc, err := stdnet.ListenPacket("udp", "127.0.0.1:12398")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		tmp := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(tmp)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), tmp[:n]...), addr)
		}
	}()
}

func testServer(t *testing.T) (*Server, *fakeDispatcher) {
	t.Helper()
	s := &Server{
		sessions: make(map[netip.Addr]*masqueSession),
		mtu:      defaultMTU,
		advertised: []AddressRange{
			{Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255")},
			{Start: netip.MustParseAddr("::"), End: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		},
	}
	v := account.NewValidator()
	mu, err := (&account.Account{Username: "tu", Password: "uuid-test"}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Add(&protocol.MemoryUser{Email: "user@1", Account: mu}); err != nil {
		t.Fatal(err)
	}
	s.validator = v
	s.pools = []*addressPool{newAddressPool(netip.MustParsePrefix("10.99.0.1/24"))}
	s.serverAddrs = []netip.Addr{netip.MustParseAddr("10.99.0.1")}
	ipstack, err := newIPStack(s.mtu, s.serverAddrs, s.handleTCPForward)
	if err != nil {
		t.Fatal(err)
	}
	s.ipstack = ipstack
	fd := &fakeDispatcher{}
	var d routing.Dispatcher = fd
	s.dispatcher.Store(&d)
	go s.drainStack()
	return s, fd
}

// readCapsules reads count capsules from the test side of the stream.
func readCapsules(t *testing.T, r *bufio.Reader, count int) []capsule {
	t.Helper()
	var out []capsule
	for len(out) < count {
		_ = r // placeholder
		cap, err := readCapsule(r)
		if err != nil {
			t.Fatalf("read capsule: %v", err)
		}
		out = append(out, cap)
	}
	return out
}

func TestMasqueTunnelTCPAndUDP(t *testing.T) {
	startTCPEcho(t)
	startUDPEcho(t)
	s, fd := testServer(t)
	fc := newFakeConn("tu", "uuid-test")

	procErr := make(chan error, 1)
	go func() {
		procErr <- s.Process(context.Background(), xnet.Network_TCP, fc, fd)
	}()

	// Server must send ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT.
	peerR := bufio.NewReader(fc.peerR)
	caps := readCapsules(t, peerR, 2)
	if caps[0].typ != capsuleTypeAddressAssign {
		t.Fatalf("first capsule: %d", caps[0].typ)
	}
	addrs, err := parseAddrEntries(caps[0].payload)
	if err != nil || len(addrs) == 0 {
		t.Fatalf("assign: %v %+v", err, addrs)
	}
	clientIP := addrs[0].Prefix.Addr()
	t.Logf("assigned: %v", addrs)
	if caps[1].typ != capsuleTypeRouteAdvertisement {
		t.Fatalf("second capsule: %d", caps[1].typ)
	}

	// ── TCP through client-side gvisor stack ──
	clientStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	clientLink := channel.New(64, 1280, tcpip.LinkAddress([]byte{0x02, 0xaa}))
	if err := clientStack.CreateNIC(1, clientLink); err != nil {
		t.Fatal(err)
	}
	a4 := clientIP.As4()
	if err := clientStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4Slice(a4[:]), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	clientStack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	// Bridge client stack <-> datagrams (single consumer of server->client
	// datagrams: TCP goes to the client stack, UDP goes to udpCh).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udpCh := make(chan []byte, 64)
	go func() {
		for {
			pb := clientLink.ReadContext(ctx)
			if pb == nil {
				return
			}
			raw := append([]byte(nil), pb.ToView().AsSlice()...)
			pb.DecRef()
			select {
			case fc.dgramToServer <- prependContextZero(raw):
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case d := <-fc.dgramToClient:
				pkt, ok := stripContextZero(d)
				if !ok {
					continue
				}
				_, _, proto, valid := parseIPPacket(pkt)
				if !valid {
					continue
				}
				if proto == 17 {
					// Hand to the UDP assertion below (single consumer).
					select {
					case udpCh <- append([]byte(nil), pkt...):
					case <-ctx.Done():
						return
					}
					continue
				}
				pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), pkt...))})
				clientLink.InjectInbound(ipv4.ProtocolNumber, pb)
			}
		}
	}()

	var wq waiter.Queue
	ep, epErr := clientStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if epErr != nil {
		t.Fatal(epErr)
	}
	dst := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice([]byte{10, 99, 0, 1}), Port: 12399}
	connectErr := make(chan tcpip.Error, 1)
	go func() {
		wqEvent, ch := waiter.NewChannelEntry(waiter.EventOut)
		wq.EventRegister(&wqEvent)
		defer wq.EventUnregister(&wqEvent)
		if terr := ep.Connect(dst); terr != nil {
			if _, started := terr.(*tcpip.ErrConnectStarted); !started {
				connectErr <- terr
				return
			}
			select {
			case <-ch:
				connectErr <- nil
			case <-time.After(5 * time.Second):
				connectErr <- &tcpip.ErrTimeout{}
			}
			return
		}
		connectErr <- nil
	}()
	if terr := <-connectErr; terr != nil {
		t.Fatalf("client TCP connect: %v", terr)
	}
	tcpConn := gonet.NewTCPConn(&wq, ep)
	defer tcpConn.Close()
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tcpConn.Write([]byte("hello-masque")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 64)
	n, err := io.ReadFull(tcpConn, reply[:len("hello-masque")])
	if err != nil || string(reply[:n]) != "hello-masque" {
		t.Fatalf("tcp echo: %q %v", reply[:n], err)
	}
	tcpConn.Close()

	// ── TCP to a NON-server address (exercises DNAT + un-DNAT) ──
	var wq2 waiter.Queue
	ep2, epErr2 := clientStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq2)
	if epErr2 != nil {
		t.Fatal(epErr2)
	}
	dst2 := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice([]byte{10, 99, 0, 200}), Port: 12399}
	dialDone := make(chan tcpip.Error, 1)
	go func() {
		wqEvent, ch := waiter.NewChannelEntry(waiter.EventOut)
		wq2.EventRegister(&wqEvent)
		defer wq2.EventUnregister(&wqEvent)
		if terr := ep2.Connect(dst2); terr != nil {
			if _, started := terr.(*tcpip.ErrConnectStarted); !started {
				dialDone <- terr
				return
			}
			select {
			case <-ch:
				dialDone <- nil
			case <-time.After(5 * time.Second):
				dialDone <- &tcpip.ErrTimeout{}
			}
			return
		}
		dialDone <- nil
	}()
	if terr := <-dialDone; terr != nil {
		t.Fatalf("client TCP connect (dnat): %v", terr)
	}
	tcpConn2 := gonet.NewTCPConn(&wq2, ep2)
	defer tcpConn2.Close()
	_ = tcpConn2.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tcpConn2.Write([]byte("hello-dnat")); err != nil {
		t.Fatal(err)
	}
	reply2 := make([]byte, 64)
	n2, err := io.ReadFull(tcpConn2, reply2[:len("hello-dnat")])
	if err != nil || string(reply2[:n2]) != "hello-dnat" {
		t.Fatalf("tcp dnat echo: %q %v", reply2[:n2], err)
	}
	if got := fd.lastTCP.Address.String(); got != "10.99.0.200" {
		t.Fatalf("dispatch dst = %v, want 10.99.0.200 (DNAT restore broken)", got)
	}

	// ── UDP via raw crafted packet ──
	udpReq := buildIPv4UDP(clientIP, netip.MustParseAddr("10.99.0.1"), 40000, 12398, []byte("ping-udp"))
	select {
	case fc.dgramToServer <- prependContextZero(udpReq):
	case <-time.After(5 * time.Second):
		t.Fatal("udp send blocked")
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		select {
		case pkt := <-udpCh:
			off := 20
			payload := pkt[off+8:]
			if string(payload) == "echo:ping-udp" {
				goto done
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("udp echo timeout")
		}
	}
done:
	fc.Close()
	select {
	case err := <-procErr:
		t.Logf("process returned: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Process did not return after Close")
	}
}
