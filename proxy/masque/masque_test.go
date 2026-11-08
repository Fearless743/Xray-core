package masque

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestVarintRoundtrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 63, 64, 15293, 16383, 16384, 1 << 30, 1<<62 - 1} {
		enc := encodeVarint(n)
		v, l, ok := decodeVarint(enc)
		if !ok || v != n || l != len(enc) {
			t.Fatalf("varint %d -> %x -> %d,%d,%v", n, enc, v, l, ok)
		}
	}
}

func TestAddressEntriesRoundtrip(t *testing.T) {
	addrs := []AssignedAddress{
		{RequestID: 7, Prefix: netip.MustParsePrefix("10.0.0.5/32")},
		{RequestID: 300, Prefix: netip.MustParsePrefix("fd00::5/128")},
	}
	raw := encodeAddressCapsule(capsuleTypeAddressAssign, addrs)
	typ, n, ok := decodeVarint(raw)
	if !ok || typ != capsuleTypeAddressAssign {
		t.Fatalf("capsule type: %d %v", typ, ok)
	}
	ln, m, ok := decodeVarint(raw[n:])
	if !ok {
		t.Fatal("no length")
	}
	got, err := parseAddrEntries(raw[n+m : n+m+int(ln)])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RequestID != 7 || got[0].Prefix.Addr().String() != "10.0.0.5" {
		t.Fatalf("addr entries: %+v", got)
	}
	if got[1].RequestID != 300 || got[1].Prefix.Addr().String() != "fd00::5" {
		t.Fatalf("addr entries v6: %+v", got)
	}
}

func TestRouteEntriesRoundtrip(t *testing.T) {
	routes := []AddressRange{
		{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.255.255.255")},
		{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ffff"), Protocol: 6},
	}
	raw := encodeRouteCapsule(routes)
	typ, n, ok := decodeVarint(raw)
	if !ok || typ != capsuleTypeRouteAdvertisement {
		t.Fatalf("capsule type: %d %v", typ, ok)
	}
	ln, m, ok := decodeVarint(raw[n:])
	if !ok {
		t.Fatal("no length")
	}
	got, err := parseRouteEntries(raw[n+m : n+m+int(ln)])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Start.String() != "10.0.0.0" || got[0].End.String() != "10.255.255.255" {
		t.Fatalf("routes: %+v", got)
	}
	if !got[1].Contains(netip.MustParseAddr("2001:db8::1"), 6) || got[1].Contains(netip.MustParseAddr("2001:db8::1"), 17) {
		t.Fatalf("protocol matching broken: %+v", got[1])
	}
	if !routes[0].Contains(netip.MustParseAddr("10.1.2.3"), 0) {
		t.Fatal("proto 0 should match all")
	}
}

func TestPoolAllocateRelease(t *testing.T) {
	p := newAddressPool(netip.MustParsePrefix("10.0.0.1/29")) // 8 addrs, .1 server
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		a, ok := p.allocate()
		if !ok {
			t.Fatalf("allocation %d failed", i)
		}
		if a.String() == "10.0.0.1" {
			t.Fatal("server address allocated to client")
		}
		seen[a.String()] = true
	}
	if _, ok := p.allocate(); ok {
		t.Fatal("pool should be exhausted (/29 minus network .0 and server .1 = 6 usable)")
	}
	_ = seen
	// release one and re-allocate
	for s := range seen {
		addr := netip.MustParseAddr(s)
		p.release(addr)
		a, ok := p.allocate()
		if !ok || a != addr {
			t.Fatalf("re-allocate after release: %v %v", a, ok)
		}
		break
	}
}

func TestUDPBuildersParseRoundtrip(t *testing.T) {
	payload := []byte("hello-masque")
	pkt := buildIPv4UDP(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 40000, 53, payload)
	src, dst, proto, valid := parseIPPacket(pkt)
	if !valid || proto != 17 || src.String() != "10.0.0.5" || dst.String() != "8.8.8.8" {
		t.Fatalf("v4 parse: %v %v %d %v", src, dst, proto, valid)
	}
	// verify IPv4 header checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if ^uint16(sum) != 0 {
		t.Fatal("v4 header checksum invalid")
	}
	// verify UDP checksum
	udp := pkt[20:]
	s4, d4 := src.As4(), dst.As4()
	var usum uint32
	usum += uint32(s4[0])<<8 | uint32(s4[1])
	usum += uint32(s4[2])<<8 | uint32(s4[3])
	usum += uint32(d4[0])<<8 | uint32(d4[1])
	usum += uint32(d4[2])<<8 | uint32(d4[3])
	usum += 17 + uint32(len(udp))
	stored := uint16(udp[6])<<8 | uint16(udp[7])
	udp[6], udp[7] = 0, 0
	got := checksumFold(sumBytes(usum, udp))
	if got != stored {
		t.Fatalf("v4 udp checksum: got %04x want %04x", got, stored)
	}

	pkt6 := buildIPv6UDP(netip.MustParseAddr("fd00::5"), netip.MustParseAddr("2001:db8::1"), 40001, 443, payload)
	src6, dst6, proto6, valid6 := parseIPPacket(pkt6)
	if !valid6 || proto6 != 17 || src6.String() != "fd00::5" || dst6.String() != "2001:db8::1" {
		t.Fatalf("v6 parse: %v %v %d %v", src6, dst6, proto6, valid6)
	}
	udp6 := pkt6[40:]
	s16, dd16 := src6.As16(), dst6.As16()
	var u6sum uint32
	for i := 0; i < 16; i += 2 {
		u6sum += uint32(s16[i])<<8 | uint32(s16[i+1])
		u6sum += uint32(dd16[i])<<8 | uint32(dd16[i+1])
	}
	u6sum += uint32(len(udp6)) + 17
	stored6 := uint16(udp6[6])<<8 | uint16(udp6[7])
	udp6[6], udp6[7] = 0, 0
	if got := checksumFold(sumBytes(u6sum, udp6)); got != stored6 {
		t.Fatalf("v6 udp checksum: got %04x want %04x", got, stored6)
	}
}

func TestDecrementHopLimit(t *testing.T) {
	pkt := buildIPv4UDP(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8"), 1, 2, []byte("x"))
	if pkt[8] != 64 {
		t.Fatal("ttl preset")
	}
	if !decrementHopLimit(pkt) || pkt[8] != 63 {
		t.Fatal("ttl not decremented")
	}
	// checksum must still be valid
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if ^uint16(sum) != 0 {
		t.Fatal("checksum broken after ttl decrement")
	}
	pkt[8] = 1
	if decrementHopLimit(pkt) {
		t.Fatal("should expire at ttl 1")
	}
}

func TestStripContext(t *testing.T) {
	pkt := []byte{1, 2, 3}
	d := prependContextZero(pkt)
	if len(d) != 4 || d[0] != 0 {
		t.Fatal("context prefix")
	}
	got, ok := stripContextZero(d)
	if !ok || !bytes.Equal(got, pkt) {
		t.Fatal("strip failed")
	}
	if _, ok := stripContextZero([]byte{0x40}); ok {
		t.Fatal("should reject nonzero context")
	}
}
