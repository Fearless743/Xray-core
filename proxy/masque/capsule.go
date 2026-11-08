package masque

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
)

// Capsule types (RFC 9297 + RFC 9484 CONNECT-IP).
const (
	capsuleTypeDatagram           = 0x00
	capsuleTypeAddressAssign      = 0x01
	capsuleTypeAddressRequest     = 0x02
	capsuleTypeRouteAdvertisement = 0x03
	maxCapsulePayload             = 1 << 20
)

// AssignedAddress mirrors an ADDRESS_ASSIGN / ADDRESS_REQUEST entry:
// request ID + IP prefix (address must be the masked network address for
// server-originated entries; clients may send host addresses with prefix).
type AssignedAddress struct {
	RequestID uint64
	Prefix    netip.Prefix
}

// AddressRange mirrors a ROUTE_ADVERTISEMENT entry. Protocol is the IP
// protocol number; 0 means all protocols (Fboard convention).
type AddressRange struct {
	Start    netip.Addr
	End      netip.Addr
	Protocol uint8
}

// Contains reports whether addr (of protocol proto) is inside the range.
func (r AddressRange) Contains(addr netip.Addr, proto uint8) bool {
	if !addr.IsValid() || addr.BitLen() != r.Start.BitLen() {
		return false
	}
	if r.Protocol != 0 && proto != 0 && r.Protocol != proto {
		return false
	}
	return r.Start.Compare(addr) <= 0 && addr.Compare(r.End) <= 0
}

// ─── QUIC variable-length integers (RFC 9000 §16) ───────────────────────────

func encodeVarint(n uint64) []byte {
	switch {
	case n < 1<<6:
		return []byte{byte(n)}
	case n < 1<<14:
		return []byte{byte(0x40 | (n >> 8)), byte(n)}
	case n < 1<<30:
		return []byte{byte(0x80 | (n >> 24)), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		out := make([]byte, 8)
		out[0] = byte(0xC0 | (n >> 56))
		for i := 1; i < 8; i++ {
			out[i] = byte(n >> (56 - 8*i))
		}
		return out
	}
}

func decodeVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	prefix := b[0] >> 6
	length := 1 << prefix
	if len(b) < length {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3F)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, length, true
}

func readVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	length := 1 << (first[0] >> 6)
	rest := make([]byte, length-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return 0, err
	}
	v, _, _ := decodeVarint(append(first[:], rest...))
	return v, nil
}

// ─── Capsule framing ────────────────────────────────────────────────────────

type capsule struct {
	typ     uint64
	payload []byte
}

func encodeCapsule(typ uint64, payload []byte) []byte {
	out := encodeVarint(typ)
	out = append(out, encodeVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func readCapsule(r io.Reader) (capsule, error) {
	typ, err := readVarint(r)
	if err != nil {
		return capsule{}, err
	}
	length, err := readVarint(r)
	if err != nil {
		return capsule{}, err
	}
	if length > maxCapsulePayload {
		return capsule{}, errors.New("masque: capsule too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return capsule{}, err
	}
	return capsule{typ: typ, payload: payload}, nil
}

// ─── Address / route entries ────────────────────────────────────────────────

func appendAddrEntry(out []byte, requestID uint64, prefix netip.Prefix) []byte {
	out = append(out, encodeVarint(requestID)...)
	addr := prefix.Addr()
	if addr.Is4() {
		out = append(out, 4)
		b := addr.As4()
		out = append(out, b[:]...)
	} else {
		out = append(out, 6)
		b := addr.As16()
		out = append(out, b[:]...)
	}
	return append(out, byte(prefix.Bits()))
}

func parseAddrEntries(payload []byte) ([]AssignedAddress, error) {
	var out []AssignedAddress
	for len(payload) > 0 {
		requestID, n, ok := decodeVarint(payload)
		if !ok {
			return nil, errors.New("masque: truncated address request ID")
		}
		payload = payload[n:]
		if len(payload) < 1 {
			return nil, errors.New("masque: truncated address version")
		}
		var addrLen int
		switch payload[0] {
		case 4:
			addrLen = 4
		case 6:
			addrLen = 16
		default:
			return nil, errors.New("masque: invalid address version")
		}
		payload = payload[1:]
		if len(payload) < addrLen+1 {
			return nil, errors.New("masque: truncated address")
		}
		addr, ok := netip.AddrFromSlice(payload[:addrLen])
		if !ok {
			return nil, errors.New("masque: invalid address bytes")
		}
		prefixLen := int(payload[addrLen])
		payload = payload[addrLen+1:]
		if prefixLen > addr.BitLen() {
			return nil, errors.New("masque: invalid prefix length")
		}
		addr = addr.Unmap()
		out = append(out, AssignedAddress{
			RequestID: requestID,
			Prefix:    netip.PrefixFrom(addr, prefixLen),
		})
	}
	return out, nil
}

func encodeAddressCapsule(typ uint64, addrs []AssignedAddress) []byte {
	var payload []byte
	for _, a := range addrs {
		payload = appendAddrEntry(payload, a.RequestID, a.Prefix.Masked())
	}
	return encodeCapsule(typ, payload)
}

func appendRouteEntry(out []byte, r AddressRange) []byte {
	if r.Start.Is4() {
		out = append(out, 4)
		b := r.Start.As4()
		out = append(out, b[:]...)
		b = r.End.As4()
		out = append(out, b[:]...)
	} else {
		out = append(out, 6)
		b := r.Start.As16()
		out = append(out, b[:]...)
		b = r.End.As16()
		out = append(out, b[:]...)
	}
	return append(out, r.Protocol)
}

func encodeRouteCapsule(routes []AddressRange) []byte {
	var payload []byte
	for _, r := range routes {
		payload = appendRouteEntry(payload, r)
	}
	return encodeCapsule(capsuleTypeRouteAdvertisement, payload)
}

func parseRouteEntries(payload []byte) ([]AddressRange, error) {
	var out []AddressRange
	for len(payload) > 0 {
		if len(payload) < 1 {
			return nil, errors.New("masque: truncated route version")
		}
		var addrLen int
		switch payload[0] {
		case 4:
			addrLen = 4
		case 6:
			addrLen = 16
		default:
			return nil, errors.New("masque: invalid route version")
		}
		payload = payload[1:]
		if len(payload) < addrLen*2+1 {
			return nil, errors.New("masque: truncated route")
		}
		start, ok1 := netip.AddrFromSlice(payload[:addrLen])
		end, ok2 := netip.AddrFromSlice(payload[addrLen : addrLen*2])
		proto := payload[addrLen*2]
		payload = payload[addrLen*2+1:]
		if !ok1 || !ok2 {
			return nil, errors.New("masque: invalid route addresses")
		}
		start, end = start.Unmap(), end.Unmap()
		if start.Compare(end) > 0 {
			return nil, errors.New("masque: invalid route range")
		}
		out = append(out, AddressRange{Start: start, End: end, Protocol: proto})
	}
	return out, nil
}

// ─── Datagram context ───────────────────────────────────────────────────────

// prependContextZero prefixes an IP packet with context ID 0 for HTTP Datagrams.
func prependContextZero(pkt []byte) []byte {
	out := make([]byte, 0, len(pkt)+1)
	out = append(out, 0x00)
	return append(out, pkt...)
}

// stripContextZero validates and strips the context ID; context must be 0.
func stripContextZero(datagram []byte) ([]byte, bool) {
	id, n, ok := decodeVarint(datagram)
	if !ok || id != 0 || len(datagram) == n {
		return nil, false
	}
	return datagram[n:], true
}

// ─── IP helpers ─────────────────────────────────────────────────────────────

func ipVersion(pkt []byte) int {
	if len(pkt) < 1 {
		return 0
	}
	return int(pkt[0] >> 4)
}

// parseIPPacket extracts src/dst/protocol from an IPv4 or IPv6 packet.
// IPv6 packets with extension headers are rejected (unsupported).
func parseIPPacket(pkt []byte) (src, dst netip.Addr, proto uint8, valid bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	switch ipVersion(pkt) {
	case 4:
		ihl := int(pkt[0]&0x0F) * 4
		if ihl < 20 || len(pkt) < ihl {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		if total > len(pkt) || total < ihl {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		src, _ = netip.AddrFromSlice(pkt[12:16])
		dst, _ = netip.AddrFromSlice(pkt[16:20])
		return src, dst, pkt[9], true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		next := pkt[6]
		// Only handle packets without extension headers.
		if next != 6 && next != 17 && next != 1 && next != 58 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		src, _ = netip.AddrFromSlice(pkt[8:24])
		dst, _ = netip.AddrFromSlice(pkt[24:40])
		return src, dst, next, true
	}
	return netip.Addr{}, netip.Addr{}, 0, false
}

// decrementHopLimit decrements IPv4 TTL / IPv6 Hop Limit in place.
// Returns false when the packet expires (caller must drop / ICMP-exceed it).
func decrementHopLimit(pkt []byte) bool {
	switch ipVersion(pkt) {
	case 4:
		if len(pkt) < 20 {
			return false
		}
		if pkt[8] <= 1 {
			return false
		}
		pkt[8]--
		fixIPv4Checksum(pkt)
		return true
	case 6:
		if len(pkt) < 40 || pkt[7] <= 1 {
			return false
		}
		pkt[7]--
		return true
	}
	return false
}

// fixIPv4Checksum recomputes the IPv4 header checksum in place.
func fixIPv4Checksum(pkt []byte) {
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return
	}
	pkt[10], pkt[11] = 0, 0
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))
}
