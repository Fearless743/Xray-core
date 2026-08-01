package shadowquic

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowquic/account"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get shadowquic user").Base(err).AtError()
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

func (s *Server) ShadowquicInboundValidator() *account.Validator { return s.validator }

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}
func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}
func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}
func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// packetConn is implemented by transport/internet/shadowquic.UDPConn
type packetConn interface {
	ReadPacket() ([]byte, xnet.Destination, error)
	WritePacket(data []byte, dest xnet.Destination) error
	Target() xnet.Destination
}

type targetConn interface {
	Target() xnet.Destination
}

type userConn interface {
	User() *protocol.MemoryUser
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowquic"
	inbound.CanSpliceCopy = 3

	iConn := stat.TryUnwrapStatsConn(conn)

	var useremail string
	var userlevel uint32
	if v, ok := iConn.(userConn); ok {
		inbound.User = v.User()
		if inbound.User != nil {
			useremail = inbound.User.Email
			userlevel = inbound.User.Level
		}
	}

	// UDP association path
	if pc, ok := iConn.(packetConn); ok {
		return s.handleUDP(ctx, conn, pc, dispatcher, useremail)
	}

	// TCP stream path
	var dest xnet.Destination
	if t, ok := iConn.(targetConn); ok {
		dest = t.Target()
	}
	if !dest.IsValid() {
		return errors.New("shadowquic: missing target from transport")
	}

	sessionPolicy := s.policyManager.ForLevel(userlevel)
	_ = conn.SetReadDeadline(time.Time{})

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  useremail,
	})
	errors.LogInfo(ctx, "tunnelling request to ", dest)

	return s.relay(ctx, sessionPolicy, dest, buf.NewReader(conn), buf.NewWriter(conn), dispatcher)
}

func (s *Server) handleUDP(ctx context.Context, conn stat.Connection, pc packetConn, dispatcher routing.Dispatcher, email string) error {
	payload, dest, err := pc.ReadPacket()
	if err != nil {
		return err
	}
	if !dest.IsValid() {
		dest = pc.Target()
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  email,
	})

	reader := &udpReader{pc: pc, first: payload, firstDest: dest}
	writer := &udpWriter{pc: pc, defaultDest: dest}
	return dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: reader,
		Writer: writer,
	})
}

func (s *Server) relay(ctx context.Context, sessionPolicy policy.Session, destination xnet.Destination,
	clientReader buf.Reader, clientWriter buf.Writer, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("failed to dispatch request to ", destination).Base(err)
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(clientReader, link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, clientWriter, buf.UpdateActivity(timer))
	}
	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("connection ends").Base(err)
	}
	return nil
}

type udpReader struct {
	pc        packetConn
	first     []byte
	firstDest xnet.Destination
	done      bool
}

func (r *udpReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !r.done {
		r.done = true
		b := buf.FromBytes(r.first)
		b.UDP = &r.firstDest
		return buf.MultiBuffer{b}, nil
	}
	payload, dest, err := r.pc.ReadPacket()
	if err != nil {
		return nil, err
	}
	b := buf.FromBytes(payload)
	b.UDP = &dest
	return buf.MultiBuffer{b}, nil
}

type udpWriter struct {
	pc          packetConn
	defaultDest xnet.Destination
}

func (w *udpWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		dest := w.defaultDest
		if b.UDP != nil {
			dest = *b.UDP
		}
		if err := w.pc.WritePacket(b.Bytes(), dest); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	buf.ReleaseMulti(mb)
	return nil
}

var _ proxy.UserManager = (*Server)(nil)
