package masque

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/stat"

	"github.com/apernet/quic-go/http3"
)

// sessionConn is handed to the proxy layer for each accepted CONNECT-IP
// tunnel. It exposes the hijacked HTTP/3 stream (capsule bytes) plus
// HTTP Datagram send/receive, and the verified user credentials.
type sessionConn interface {
	stat.Connection
	Credentials() (username, password string)
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

var _ sessionConn = (*Conn)(nil)

// Conn wraps a hijacked HTTP/3 extended-CONNECT stream.
type Conn struct {
	stream   *http3.Stream
	local    net.Addr
	remote   net.Addr
	username string
	password string

	closeOnce sync.Once
	closeErr  error
}

func (c *Conn) Credentials() (string, string) { return c.username, c.password }

func (c *Conn) SendDatagram(b []byte) error { return c.stream.SendDatagram(b) }

func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.stream.ReceiveDatagram(ctx)
}

func (c *Conn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *Conn) Write(b []byte) (int, error) { return c.stream.Write(b) }

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.stream.CancelRead(0)
		c.stream.CancelWrite(0)
		c.closeErr = c.stream.Close()
	})
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

func (c *Conn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// errConnClosed reports whether err is caused by our own Close.
func errConnClosed(err error) bool {
	return err != nil && errors.Cause(err) == context.Canceled
}
