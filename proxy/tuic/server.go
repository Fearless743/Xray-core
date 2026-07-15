package tuic

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/tuic/account"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Address type constants for TUIC protocol over TCP.
// 0x01 = IPv4 (4 bytes)
// 0x02 = Domain (1 byte length + name)
// 0x03 = IPv6 (16 bytes)
var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, xnet.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x02, xnet.AddressFamilyDomain),
	protocol.AddressFamilyByte(0x03, xnet.AddressFamilyIPv6),
)

const (
	commandTCP byte = 0x01
	commandUDP byte = 0x03
)

// Server is an inbound connection handler for the TUIC protocol over TCP.
type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
}

// NewServer creates a new TUIC inbound handler.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get tuic user").Base(err).AtError()
		}
		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}

	v := core.MustFromContext(ctx)
	return &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

// Network returns the networks this inbound handler works on.
// TCP only -- UDP is tunneled over TCP connections.
func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// Process implements proxy.Inbound.Process().
//
// Protocol flow over TCP:
//
//	1. Auth frame: [0x00 auth_type(1)] [password_len(1)] [password]
//	2. Command + address: [command(1)] [addr_type(1)] [addr(var)] [port(2)]
//	   command: 0x01 = TCP, 0x03 = UDP
//	   addr_type: 0x01 = IPv4, 0x02 = Domain, 0x03 = IPv6
//	3. For TCP: raw bidirectional data
//	   For UDP: framed packets [addr_type(1)] [addr(var)] [port(2)] [data_len(2)] [data]
func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Set handshake deadline
	sessionPolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	// ---- 1. Auth frame: [auth_type(1)] [password_len(1)] [password] ----
	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHeader); err != nil {
		return errors.New("tuic: failed to read auth header").Base(err)
	}
	if authHeader[0] != 0x00 {
		return errors.New("tuic: unsupported auth type, expected 0x00")
	}
	passLen := int(authHeader[1])
	password := make([]byte, passLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return errors.New("tuic: failed to read password").Base(err)
	}

	user := s.validator.Get(string(password))
	if user == nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: errors.New("tuic: invalid user"),
		})
		return errors.New("tuic: authentication failed")
	}

	inbound := session.InboundFromContext(ctx)
	inbound.Name = "tuic"
	inbound.User = user
	sessionPolicy = s.policyManager.ForLevel(user.Level)

	// ---- 2. Command + address ----
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		return errors.New("tuic: failed to read command").Base(err)
	}

	addr, port, err := addrParser.ReadAddressPort(nil, conn)
	if err != nil {
		return errors.New("tuic: failed to read address").Base(err)
	}

	// Clear read deadline for data transfer
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	switch cmdBuf[0] {
	case commandUDP:
		dest := xnet.UDPDestination(addr, port)
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     dest,
			Status: log.AccessAccepted,
			Reason: "",
			Email:  user.Email,
		})
		errors.LogInfo(ctx, "tunnelling UDP request to ", dest)
		return s.handleUDPPayload(ctx, sessionPolicy, conn, dispatcher)

	default: // commandTCP
		destination := xnet.TCPDestination(addr, port)
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     destination,
			Status: log.AccessAccepted,
			Reason: "",
			Email:  user.Email,
		})
		errors.LogInfo(ctx, "tunnelling request to ", destination)
		return s.handleConnection(ctx, sessionPolicy, destination, conn, dispatcher)
	}
}

// handleConnection handles a TCP relay with bidirectional copy.
func (s *Server) handleConnection(ctx context.Context, sessionPolicy policy.Session,
	destination xnet.Destination, conn stat.Connection, dispatcher routing.Dispatcher,
) error {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("failed to dispatch request to ", destination).Base(err)
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if err := buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transfer request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to write response").Base(err)
		}
		return nil
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("connection ends").Base(err)
	}
	return nil
}

// handleUDPPayload handles UDP relay over the TCP connection.
// Each UDP packet is self-addressed:
//
//	[addr_type(1)] [addr(var)] [port(2)] [data_len(2)] [data]
func (s *Server) handleUDPPayload(ctx context.Context, sessionPolicy policy.Session,
	conn stat.Connection, dispatcher routing.Dispatcher,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	clientReader := &PacketReader{Reader: conn}
	clientWriter := &PacketWriter{Writer: conn}

	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		udpPayload := packet.Payload
		if udpPayload.UDP == nil {
			udpPayload.UDP = &packet.Source
		}
		if err := clientWriter.WriteMultiBuffer(buf.MultiBuffer{udpPayload}); err != nil {
			errors.LogWarningInner(ctx, err, "failed to write UDP response")
			cancel()
		} else {
			timer.Update()
		}
	})
	defer udpServer.RemoveRay()

	inbound := session.InboundFromContext(ctx)

	requestDone := func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			mb, err := clientReader.ReadMultiBuffer()
			if err != nil {
				if errors.Cause(err) != io.EOF {
					return errors.New("failed to read UDP request").Base(err)
				}
				return nil
			}
			timer.Update()

			mb2, b := buf.SplitFirst(mb)
			if b == nil {
				continue
			}
			destination := *b.UDP

			currentPacketCtx := ctx
			if inbound != nil && inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     destination,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  inbound.User.Email,
				})
			}
			errors.LogInfo(ctx, "tunnelling UDP packet to ", destination)

			udpServer.Dispatch(currentPacketCtx, destination, b)
			for _, payload := range mb2 {
				udpServer.Dispatch(currentPacketCtx, destination, payload)
			}
		}
	}

	if err := task.Run(ctx, requestDone); err != nil {
		return errors.New("tuic UDP handling ended").Base(err)
	}
	return nil
}

// PacketReader reads TUIC UDP packets from a TCP stream.
//
// Frame format (client -> server):
//
//	[addr_type(1)] [addr(var)] [port(2)] [data_len(2)] [data]
type PacketReader struct {
	io.Reader
}

// ReadMultiBuffer implements buf.Reader.
func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	addr, port, err := addrParser.ReadAddressPort(nil, r)
	if err != nil {
		return nil, errors.New("failed to read UDP address").Base(err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, errors.New("failed to read UDP payload length").Base(err)
	}
	remain := int(binary.BigEndian.Uint16(lenBuf[:]))

	dest := xnet.UDPDestination(addr, port)
	var mb buf.MultiBuffer
	for remain > 0 {
		length := buf.Size
		if remain < length {
			length = remain
		}
		b := buf.New()
		b.UDP = &dest
		mb = append(mb, b)
		n, err := b.ReadFullFrom(r, int32(length))
		if err != nil {
			buf.ReleaseMulti(mb)
			return nil, errors.New("failed to read UDP payload").Base(err)
		}
		remain -= int(n)
	}
	return mb, nil
}

// PacketWriter writes TUIC UDP packets to a TCP stream.
//
// Frame format (server -> client):
//
//	[addr_type(1)] [addr(var)] [port(2)] [data_len(2)] [data]
type PacketWriter struct {
	io.Writer
}

// WriteMultiBuffer implements buf.Writer.
func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		if b.UDP != nil {
			if _, err := w.writePacket(b.Bytes(), *b.UDP); err != nil {
				return err
			}
		}
		b.Release()
	}
	return nil
}

func (w *PacketWriter) writePacket(payload []byte, dest xnet.Destination) (int, error) {
	buffer := buf.New()
	defer buffer.Release()

	if err := addrParser.WriteAddressPort(buffer, dest.Address, dest.Port); err != nil {
		return 0, err
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := buffer.Write(lenBuf[:]); err != nil {
		return 0, err
	}
	if _, err := buffer.Write(payload); err != nil {
		return 0, err
	}

	_, err := w.Write(buffer.Bytes())
	return len(payload), err
}

// Interface compliance check
var _ proxy.UserManager = (*Server)(nil)
