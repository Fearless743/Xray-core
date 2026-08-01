package shadowquic

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/xtls/xray-core/common/protocol"
	xnet "github.com/xtls/xray-core/common/net"
)

const (
	CommandConnect           byte = 0x01
	CommandBind              byte = 0x02
	CommandAssociateDatagram byte = 0x03
	CommandAssociateStream   byte = 0x04
	CommandAuthenticate      byte = 0x05
	CommandExtension         byte = 0xff
)

const maxUDPPacketSize = 0xffff

var (
	errInvalidAddress  = errors.New("shadowquic: invalid address")
	errInvalidDatagram = errors.New("shadowquic: invalid datagram")
	errPacketTooLarge  = errors.New("shadowquic: packet too large")
)

// SOCKS5 ATYP-style address parser used by ShadowQUIC (same as mihomo socks5).
var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, xnet.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, xnet.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, xnet.AddressFamilyDomain),
)

func ReadCommand(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func ReadRequestAddr(r io.Reader) (xnet.Address, xnet.Port, error) {
	return addrParser.ReadAddressPort(nil, r)
}

func WriteUDPControl(w io.Writer, addr xnet.Address, port xnet.Port, id uint16) error {
	if err := addrParser.WriteAddressPort(w, addr, port); err != nil {
		return err
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], id)
	_, err := w.Write(buf[:])
	return err
}

func ReadUDPControl(r io.Reader) (xnet.Address, xnet.Port, uint16, error) {
	addr, port, err := addrParser.ReadAddressPort(nil, r)
	if err != nil {
		return nil, 0, 0, err
	}
	id, err := ReadUint16(r)
	if err != nil {
		return nil, 0, 0, err
	}
	return addr, port, id, nil
}

func EncodeDatagram(id uint16, payload []byte) ([]byte, error) {
	if len(payload) > maxUDPPacketSize {
		return nil, errPacketTooLarge
	}
	packet := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(packet[:2], id)
	copy(packet[2:], payload)
	return packet, nil
}

func DecodeDatagram(packet []byte) (uint16, []byte, error) {
	if len(packet) < 2 {
		return 0, nil, errInvalidDatagram
	}
	return binary.BigEndian.Uint16(packet[:2]), packet[2:], nil
}

func WritePacketStreamHeader(w io.Writer, id uint16) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], id)
	_, err := w.Write(buf[:])
	return err
}

func WritePacketStreamPayload(w io.Writer, payload []byte) error {
	if len(payload) > maxUDPPacketSize {
		return errPacketTooLarge
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(len(payload)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadUint16(r io.Reader) (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

func addressKey(addr xnet.Address, port xnet.Port) string {
	return addr.String() + ":" + port.String()
}

func destinationFromAddrPort(addr xnet.Address, port xnet.Port, network xnet.Network) xnet.Destination {
	dest := xnet.Destination{
		Address: addr,
		Port:    port,
		Network: network,
	}
	return dest
}

func destinationToAddrPort(dest xnet.Destination) (xnet.Address, xnet.Port) {
	return dest.Address, dest.Port
}

// addrString builds host:port for logging / net.Addr
func addrString(addr xnet.Address, port xnet.Port) string {
	if addr == nil {
		return ""
	}
	return net.JoinHostPort(addr.String(), port.String())
}
