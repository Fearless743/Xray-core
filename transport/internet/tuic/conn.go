package tuic

import (
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"io"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

// InterConn wraps a QUIC stream after Connect has been parsed.
type InterConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
	target net.Destination
	user   *protocol.MemoryUser
}

func (c *InterConn) User() *protocol.MemoryUser  { return c.user }
func (c *InterConn) Target() net.Destination     { return c.target }
func (c *InterConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *InterConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *InterConn) Close() error {
	c.stream.CancelRead(0)
	return c.stream.Close()
}
func (c *InterConn) LocalAddr() net.Addr                { return c.local }
func (c *InterConn) RemoteAddr() net.Addr               { return c.remote }
func (c *InterConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *InterConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *InterConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// UDPConn presents a single UDP association as a connection for the proxy layer.
type UDPConn struct {
	local  net.Addr
	remote net.Addr
	user   *protocol.MemoryUser
	target net.Destination

	readCh  chan udpMsg
	writeFn func(data []byte, dest net.Destination) error
	closeFn func()

	closed bool
	mu     sync.Mutex
}

type udpMsg struct {
	data []byte
	dest net.Destination
}

func (c *UDPConn) User() *protocol.MemoryUser { return c.user }
func (c *UDPConn) Target() net.Destination    { return c.target }

func (c *UDPConn) ReadPacket() ([]byte, net.Destination, error) {
	msg, ok := <-c.readCh
	if !ok {
		return nil, net.Destination{}, io.EOF
	}
	return msg.data, msg.dest, nil
}

func (c *UDPConn) WritePacket(data []byte, dest net.Destination) error {
	return c.writeFn(data, dest)
}

func (c *UDPConn) feed(data []byte, dest net.Destination) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.readCh <- udpMsg{data: data, dest: dest}:
	default:
	}
}

func (c *UDPConn) Read(b []byte) (int, error) {
	data, _, err := c.ReadPacket()
	if err != nil {
		return 0, err
	}
	return copy(b, data), nil
}

func (c *UDPConn) Write(b []byte) (int, error) {
	if err := c.WritePacket(b, c.target); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *UDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.readCh)
		if c.closeFn != nil {
			c.closeFn()
		}
	}
	return nil
}

func (c *UDPConn) LocalAddr() net.Addr                { return c.local }
func (c *UDPConn) RemoteAddr() net.Addr               { return c.remote }
func (c *UDPConn) SetDeadline(t time.Time) error      { return nil }
func (c *UDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *UDPConn) SetWriteDeadline(t time.Time) error { return nil }
