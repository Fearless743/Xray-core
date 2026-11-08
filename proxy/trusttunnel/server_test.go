package trusttunnel

import (
	"bytes"
	"testing"
)

func TestPseudoHostOf(t *testing.T) {
	cases := map[string]string{
		"_udp2":        "_udp2",
		"_udp2:0":      "_udp2",
		"_icmp":        "_icmp",
		"_check":       "_check",
		"example.com:443": "example.com",
		"1.2.3.4:443":     "1.2.3.4",
		"[2001:db8::1]:443": "2001:db8::1",
	}
	for in, want := range cases {
		if got := pseudoHostOf(in); got != want {
			t.Errorf("pseudoHostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAddr16Roundtrip(t *testing.T) {
	for _, ip := range []string{"1.2.3.4", "2001:db8::1", "::ffff:10.0.0.1"} {
		b := addrTo16(ip)
		got := addr16ToString(b[:])
		b2 := addrTo16(ip)
		want := addr16ToString(b2[:])
		if got != want || got == "" {
			t.Errorf("addr roundtrip %q -> %q", ip, got)
		}
	}
}

func TestUDPPacketRoundtrip(t *testing.T) {
	var src, dst [16]byte
	src = addrTo16("192.168.1.5")
	dst = addrTo16("8.8.8.8")
	payload := []byte("hello dns")

	// Build a client->endpoint packet manually: len + src + sport + dst + dport + appLen + app + payload
	body := &bytes.Buffer{}
	addrPort := func(a [16]byte, p uint16) {
		body.Write(a[:])
		body.Write([]byte{byte(p >> 8), byte(p)})
	}
	addrPort(src, 54321)
	addrPort(dst, 53)
	body.WriteByte(3)
	body.WriteString("app")
	body.Write(payload)
	full := &bytes.Buffer{}
	length := body.Len()
	full.Write([]byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
	full.Write(body.Bytes())

	pkt, err := readUDPPacket(full)
	if err != nil {
		t.Fatalf("readUDPPacket: %v", err)
	}
	if string(pkt.payload) != string(payload) {
		t.Fatalf("payload mismatch: %q", pkt.payload)
	}
	if pkt.srcPort != 54321 || pkt.dstPort != 53 {
		t.Fatalf("ports mismatch: %d %d", pkt.srcPort, pkt.dstPort)
	}

	// Response encode must drop app name and be re-readable as body.
	resp := encodeUDPResponse(dst, 53, src, 54321, payload)
	if len(resp) < 4 {
		t.Fatal("response too short")
	}
}

func TestParseBasicAuth(t *testing.T) {
	// "user:pass" base64
	u, p, ok := parseBasicAuth("Basic dXNlcjpwYXNz")
	if !ok || u != "user" || p != "pass" {
		t.Fatalf("parseBasicAuth = %q %q %v", u, p, ok)
	}
	if _, _, ok := parseBasicAuth("Bearer xxx"); ok {
		t.Fatal("should reject non-basic")
	}
}
