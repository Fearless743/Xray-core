package tuic

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const VER byte = 0x05

type CommandType byte

const (
	CmdAuthenticate CommandType = 0x00
	CmdConnect      CommandType = 0x01
	CmdPacket       CommandType = 0x02
	CmdDissociate   CommandType = 0x03
	CmdHeartbeat    CommandType = 0x04
)

const (
	AtypDomainName byte = 0
	AtypIPv4       byte = 1
	AtypIPv6       byte = 2
	AtypNone       byte = 255
)

type BufferedReader interface {
	io.Reader
	io.ByteReader
}

type BufferedWriter interface {
	io.Writer
	io.ByteWriter
}

type CommandHead struct {
	VER  byte
	TYPE CommandType
}

func ReadCommandHead(r BufferedReader) (CommandHead, error) {
	ver, err := r.ReadByte()
	if err != nil {
		return CommandHead{}, err
	}
	t, err := r.ReadByte()
	if err != nil {
		return CommandHead{}, err
	}
	return CommandHead{VER: ver, TYPE: CommandType(t)}, nil
}

func (c CommandHead) WriteTo(w BufferedWriter) error {
	if err := w.WriteByte(c.VER); err != nil {
		return err
	}
	return w.WriteByte(byte(c.TYPE))
}

type Authenticate struct {
	CommandHead
	UUID  [16]byte
	TOKEN [32]byte
}

func ReadAuthenticate(r BufferedReader) (Authenticate, error) {
	head, err := ReadCommandHead(r)
	if err != nil {
		return Authenticate{}, err
	}
	return ReadAuthenticateWithHead(head, r)
}

func ReadAuthenticateWithHead(head CommandHead, r BufferedReader) (Authenticate, error) {
	if head.TYPE != CmdAuthenticate {
		return Authenticate{}, fmt.Errorf("expected Authenticate, got %d", head.TYPE)
	}
	var a Authenticate
	a.CommandHead = head
	if _, err := io.ReadFull(r, a.UUID[:]); err != nil {
		return a, err
	}
	if _, err := io.ReadFull(r, a.TOKEN[:]); err != nil {
		return a, err
	}
	return a, nil
}

type Connect struct {
	CommandHead
	ADDR Address
}

func ReadConnect(r BufferedReader) (Connect, error) {
	head, err := ReadCommandHead(r)
	if err != nil {
		return Connect{}, err
	}
	if head.TYPE != CmdConnect {
		return Connect{}, fmt.Errorf("expected Connect, got %d", head.TYPE)
	}
	addr, err := ReadAddress(r)
	if err != nil {
		return Connect{}, err
	}
	return Connect{CommandHead: head, ADDR: addr}, nil
}

type Packet struct {
	CommandHead
	ASSOC_ID   uint16
	PKT_ID     uint16
	FRAG_TOTAL uint8
	FRAG_ID    uint8
	SIZE       uint16
	ADDR       Address
	DATA       []byte
}

func ReadPacketWithHead(head CommandHead, r BufferedReader) (Packet, error) {
	if head.TYPE != CmdPacket {
		return Packet{}, fmt.Errorf("expected Packet, got %d", head.TYPE)
	}
	var p Packet
	p.CommandHead = head
	if err := binary.Read(r, binary.BigEndian, &p.ASSOC_ID); err != nil {
		return p, err
	}
	if err := binary.Read(r, binary.BigEndian, &p.PKT_ID); err != nil {
		return p, err
	}
	if err := binary.Read(r, binary.BigEndian, &p.FRAG_TOTAL); err != nil {
		return p, err
	}
	if err := binary.Read(r, binary.BigEndian, &p.FRAG_ID); err != nil {
		return p, err
	}
	if err := binary.Read(r, binary.BigEndian, &p.SIZE); err != nil {
		return p, err
	}
	addr, err := ReadAddress(r)
	if err != nil {
		return p, err
	}
	p.ADDR = addr
	p.DATA = make([]byte, p.SIZE)
	if _, err := io.ReadFull(r, p.DATA); err != nil {
		return p, err
	}
	return p, nil
}

func (p Packet) WriteTo(w BufferedWriter) error {
	if err := p.CommandHead.WriteTo(w); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, p.ASSOC_ID); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, p.PKT_ID); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, p.FRAG_TOTAL); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, p.FRAG_ID); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, p.SIZE); err != nil {
		return err
	}
	if err := p.ADDR.WriteTo(w); err != nil {
		return err
	}
	_, err := w.Write(p.DATA)
	return err
}

func NewPacket(assocID, pktID uint16, fragTotal, fragID uint8, addr Address, data []byte) Packet {
	return Packet{
		CommandHead: CommandHead{VER: VER, TYPE: CmdPacket},
		ASSOC_ID:    assocID,
		PKT_ID:      pktID,
		FRAG_TOTAL:  fragTotal,
		FRAG_ID:     fragID,
		SIZE:        uint16(len(data)),
		ADDR:        addr,
		DATA:        data,
	}
}

type Dissociate struct {
	CommandHead
	ASSOC_ID uint16
}

func ReadDissociateWithHead(head CommandHead, r BufferedReader) (Dissociate, error) {
	if head.TYPE != CmdDissociate {
		return Dissociate{}, fmt.Errorf("expected Dissociate, got %d", head.TYPE)
	}
	var d Dissociate
	d.CommandHead = head
	if err := binary.Read(r, binary.BigEndian, &d.ASSOC_ID); err != nil {
		return d, err
	}
	return d, nil
}

type Address struct {
	TYPE byte
	ADDR []byte
	PORT uint16
}

func ReadAddress(r BufferedReader) (Address, error) {
	var a Address
	var err error
	a.TYPE, err = r.ReadByte()
	if err != nil {
		return a, err
	}
	switch a.TYPE {
	case AtypIPv4:
		a.ADDR = make([]byte, 4)
		if _, err = io.ReadFull(r, a.ADDR); err != nil {
			return a, err
		}
	case AtypIPv6:
		a.ADDR = make([]byte, 16)
		if _, err = io.ReadFull(r, a.ADDR); err != nil {
			return a, err
		}
	case AtypDomainName:
		var l byte
		l, err = r.ReadByte()
		if err != nil {
			return a, err
		}
		a.ADDR = make([]byte, int(l)+1)
		a.ADDR[0] = l
		if _, err = io.ReadFull(r, a.ADDR[1:]); err != nil {
			return a, err
		}
	case AtypNone:
		return a, nil
	default:
		return a, fmt.Errorf("unknown address type: %d", a.TYPE)
	}
	if err = binary.Read(r, binary.BigEndian, &a.PORT); err != nil {
		return a, err
	}
	return a, nil
}

func (a Address) WriteTo(w BufferedWriter) error {
	if err := w.WriteByte(a.TYPE); err != nil {
		return err
	}
	if a.TYPE == AtypNone {
		return nil
	}
	if _, err := w.Write(a.ADDR); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, a.PORT)
}

func (a Address) String() string {
	switch a.TYPE {
	case AtypDomainName:
		return net.JoinHostPort(string(a.ADDR[1:]), strconv.Itoa(int(a.PORT)))
	case AtypIPv4, AtypIPv6:
		return net.JoinHostPort(net.IP(a.ADDR).String(), strconv.Itoa(int(a.PORT)))
	default:
		return ""
	}
}

func AddressFromHostPort(host string, port uint16) Address {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return Address{TYPE: AtypIPv4, ADDR: v4, PORT: port}
		}
		return Address{TYPE: AtypIPv6, ADDR: ip.To16(), PORT: port}
	}
	b := make([]byte, 1+len(host))
	b[0] = byte(len(host))
	copy(b[1:], host)
	return Address{TYPE: AtypDomainName, ADDR: b, PORT: port}
}

// QUIC application error codes
const (
	ProtocolError         = 0xfffffff0
	AuthenticationFailed  = 0xfffffff1
	AuthenticationTimeout = 0xfffffff2
	BadCommand            = 0xfffffff3
)
