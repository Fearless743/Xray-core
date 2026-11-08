package masque

import (
	"context"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xtls/xray-core/common/errors"
)

const masqueNICID = 1

// ipStack bundles a gVisor netstack used to terminate client TCP (and ICMP
// to server addresses). The tunnel prefixes are assigned to the NIC so every
// address in them is treated as on-link: TCP is intercepted by the forwarder
// and dispatched via Xray. UDP is parsed and proxied manually (see server.go)
// and never enters the stack.
type ipStack struct {
	stack *stack.Stack
	link  *channel.Endpoint
	mtu   uint32
}

func newIPStack(mtu uint32, serverAddrs []netip.Addr, tcpHandler func(*tcp.ForwarderRequest)) (*ipStack, error) {
	if mtu < 1280 {
		mtu = 1280
	}
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
		},
		HandleLocal: true,
	})
	linkAddr := tcpip.LinkAddress([]byte{0x02, 0x4d, 0x41, 0x53, 0x51, 0x55}) // "MASQU"
	ep := channel.New(1024, mtu, linkAddr)
	if err := s.CreateNIC(masqueNICID, ep); err != nil {
		return nil, errors.New("masque: create NIC").Base(errToError(err))
	}
	// Spoofing allows endpoints to use non-local source addresses on the
	// return path (cf. sing-tun). Promiscuous mode is intentionally OFF:
	// it breaks transport delivery in this gVisor version.
	if err := s.SetSpoofing(masqueNICID, true); err != nil {
		return nil, errors.New("masque: spoofing mode").Base(errToError(err))
	}
	for _, addr := range serverAddrs {
		var proto tcpip.NetworkProtocolNumber
		var withPrefix tcpip.AddressWithPrefix
		if addr.Is4() {
			proto = ipv4.ProtocolNumber
			a4 := addr.As4()
			withPrefix = tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4Slice(a4[:]),
				PrefixLen: 32,
			}
		} else {
			proto = ipv6.ProtocolNumber
			a16 := addr.As16()
			withPrefix = tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16Slice(a16[:]),
				PrefixLen: 128,
			}
		}
		if err := s.AddProtocolAddress(masqueNICID, tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: withPrefix,
		}, stack.AddressProperties{}); err != nil {
			return nil, errors.New("masque: add protocol address").Base(errToError(err))
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: masqueNICID},
		{Destination: header.IPv6EmptySubnet, NIC: masqueNICID},
	})
	fwd := tcp.NewForwarder(s, 256*1024, 1024, tcpHandler)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return &ipStack{stack: s, link: ep, mtu: mtu}, nil
}

// inject delivers a raw IP packet from a client session into the stack.
func (s *ipStack) inject(pkt []byte) {
	var proto tcpip.NetworkProtocolNumber
	switch ipVersion(pkt) {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
	})
	s.link.InjectInbound(proto, pb)
}

// readOutbound blocks until the stack emits a packet (return path).
// Returns nil when ctx is cancelled.
func (s *ipStack) readOutbound(ctx context.Context) []byte {
	pb := s.link.ReadContext(ctx)
	if pb == nil {
		return nil
	}
	defer pb.DecRef()
	return append([]byte(nil), pb.ToView().AsSlice()...)
}

func errToError(e tcpip.Error) error {
	return errors.New(e.String())
}

var _ = waiter.Queue{}
