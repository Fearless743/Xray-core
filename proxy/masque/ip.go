package masque

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
)

var ipPacketID uint32

func nextPacketID() uint16 {
	return uint16(atomic.AddUint32(&ipPacketID, 1) & 0xFFFF)
}

// buildIPv4UDP builds a full IPv4+UDP packet: src -> dst.
func buildIPv4UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	if !srcIP.Is4() || !dstIP.Is4() {
		return nil
	}
	s4, d4 := srcIP.As4(), dstIP.As4()
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], nextPacketID())
	pkt[6], pkt[7] = 0x40, 0x00 // flags DF, fragment offset 0
	pkt[8] = 64                 // TTL
	pkt[9] = 17                 // UDP
	copy(pkt[10:12], []byte{0, 0})
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	fixIPv4Checksum(pkt)
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], payload)
	sum := udpChecksumV4(s4, d4, udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt
}

// buildIPv6UDP builds a full IPv6+UDP packet: src -> dst.
func buildIPv6UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	if !srcIP.Is6() || !dstIP.Is6() {
		return nil
	}
	s16, d16 := srcIP.As16(), dstIP.As16()
	pkt := make([]byte, 40+8+len(payload))
	pkt[0] = 0x60 // version 6
	// traffic class + flow label = 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	pkt[6] = 17 // next header UDP
	pkt[7] = 64 // hop limit
	copy(pkt[8:24], s16[:])
	copy(pkt[24:40], d16[:])
	udp := pkt[40:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], payload)
	sum := udpChecksumV6(s16, d16, udp)
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return pkt
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	if sum == 0 {
		return 0xFFFF // RFC 768: zero transmitted as all-ones for UDP
	}
	return ^uint16(sum)
}

func sumBytes(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func udpChecksumV4(src, dst [4]byte, udp []byte) uint16 {
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += 17 // protocol
	sum += uint32(len(udp))
	return checksumFold(sumBytes(sum, udp))
}

func udpChecksumV6(src, dst [16]byte, udp []byte) uint16 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	sum += uint32(len(udp)) // UDP length (upper-layer length, 32-bit)
	sum += 17               // next header
	return checksumFold(sumBytes(sum, udp))
}

// ─── TCP helpers (DNAT support) ────────────────────────────────────────────

// tcpSegment returns the TCP segment of an IP packet.
func tcpSegment(pkt []byte) ([]byte, bool) {
	var off int
	switch ipVersion(pkt) {
	case 4:
		if len(pkt) < 20 {
			return nil, false
		}
		off = int(pkt[0]&0x0F) * 4
	case 6:
		off = 40
	default:
		return nil, false
	}
	if len(pkt) < off+20 {
		return nil, false
	}
	return pkt[off:], true
}

// tcpPorts extracts source/destination ports from a TCP packet.
func tcpPorts(pkt []byte) (sport, dport uint16) {
	seg, ok := tcpSegment(pkt)
	if !ok {
		return 0, 0
	}
	return binary.BigEndian.Uint16(seg[0:2]), binary.BigEndian.Uint16(seg[2:4])
}

// tcpPortsAndSYN additionally reports whether the SYN flag is set.
func tcpPortsAndSYN(pkt []byte) (sport, dport uint16, isSYN bool) {
	seg, ok := tcpSegment(pkt)
	if !ok {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(seg[0:2]), binary.BigEndian.Uint16(seg[2:4]), seg[13]&0x02 != 0
}

// rewriteIPDst replaces the destination address and repairs checksums (TCP).
func rewriteIPDst(pkt []byte, newDst netip.Addr) bool {
	switch ipVersion(pkt) {
	case 4:
		if !newDst.Is4() || len(pkt) < 20 || pkt[9] != 6 {
			return false
		}
		b := newDst.As4()
		copy(pkt[16:20], b[:])
		fixIPv4Checksum(pkt)
		return fixTCPChecksumV4(pkt)
	case 6:
		if !newDst.Is6() || len(pkt) < 40 || pkt[6] != 6 {
			return false
		}
		b := newDst.As16()
		copy(pkt[24:40], b[:])
		return fixTCPChecksumV6(pkt)
	}
	return false
}

// rewriteIPSrc replaces the source address and repairs checksums (TCP).
func rewriteIPSrc(pkt []byte, newSrc netip.Addr) bool {
	switch ipVersion(pkt) {
	case 4:
		if !newSrc.Is4() || len(pkt) < 20 || pkt[9] != 6 {
			return false
		}
		b := newSrc.As4()
		copy(pkt[12:16], b[:])
		fixIPv4Checksum(pkt)
		return fixTCPChecksumV4(pkt)
	case 6:
		if !newSrc.Is6() || len(pkt) < 40 || pkt[6] != 6 {
			return false
		}
		b := newSrc.As16()
		copy(pkt[8:24], b[:])
		return fixTCPChecksumV6(pkt)
	}
	return false
}

func fixTCPChecksumV4(pkt []byte) bool {
	ihl := int(pkt[0]&0x0F) * 4
	seg := pkt[ihl:]
	if len(seg) < 20 {
		return false
	}
	seg[16], seg[17] = 0, 0
	s4, _ := netip.AddrFromSlice(pkt[12:16])
	d4, _ := netip.AddrFromSlice(pkt[16:20])
	a, b := s4.As4(), d4.As4()
	var sum uint32
	sum += uint32(a[0])<<8 | uint32(a[1])
	sum += uint32(a[2])<<8 | uint32(a[3])
	sum += uint32(b[0])<<8 | uint32(b[1])
	sum += uint32(b[2])<<8 | uint32(b[3])
	sum += 6 + uint32(len(seg))
	check := checksumFold(sumBytes(sum, seg))
	// TCP allows a zero checksum on the wire; checksumFold maps 0->0xFFFF
	// which still validates correctly.
	binary.BigEndian.PutUint16(seg[16:18], check)
	return true
}

func fixTCPChecksumV6(pkt []byte) bool {
	seg := pkt[40:]
	if len(seg) < 20 {
		return false
	}
	seg[16], seg[17] = 0, 0
	s16, _ := netip.AddrFromSlice(pkt[8:24])
	d16, _ := netip.AddrFromSlice(pkt[24:40])
	a, b := s16.As16(), d16.As16()
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(a[i])<<8 | uint32(a[i+1])
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	sum += uint32(len(seg)) + 6
	check := checksumFold(sumBytes(sum, seg))
	binary.BigEndian.PutUint16(seg[16:18], check)
	return true
}
