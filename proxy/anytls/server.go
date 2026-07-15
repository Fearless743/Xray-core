package anytls

import (
	"context"
	"io"
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
	"github.com/xtls/xray-core/proxy/anytls/account"
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
			return nil, errors.New("failed to get anytls user").Base(err).AtError()
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

func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error     { return s.validator.Add(u) }
func (s *Server) RemoveUser(ctx context.Context, e string) error                 { return s.validator.Del(e) }
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser { return s.validator.GetByEmail(email) }
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser             { return s.validator.GetAll() }
func (s *Server) GetUsersCount(context.Context) int64                            { return s.validator.GetCount() }
func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UNIX}
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "anytls"

	sessionPolicy := s.policyManager.ForLevel(0)
	common.Must(conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)))

	// Auth: 2 byte password length + password
	passLen := make([]byte, 2)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return errors.New("anytls: failed to read password length").Base(err)
	}
	pl := int(passLen[0])<<8 | int(passLen[1])
	password := make([]byte, pl)
	if _, err := io.ReadFull(conn, password); err != nil {
		return errors.New("anytls: failed to read password").Base(err)
	}

	user := s.validator.Get(string(password))
	if user == nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: errors.New("anytls: invalid user"),
		})
		return errors.New("anytls: invalid user")
	}
	inbound.User = user
	sessionPolicy = s.policyManager.ForLevel(user.Level)
	common.Must(conn.SetReadDeadline(time.Time{}))

	// Read target: 1 byte addr_type + addr + port
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(conn, addrType); err != nil {
		return errors.New("anytls: failed to read addr type").Base(err)
	}

	var dest xnet.Destination
	switch addrType[0] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return errors.New("anytls: failed to read IPv4").Base(err)
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return errors.New("anytls: failed to read port").Base(err)
		}
		dest = xnet.TCPDestination(xnet.IPAddress(ip), xnet.Port(int(port[0])<<8|int(port[1])))
	case 2:
		dl := make([]byte, 1)
		if _, err := io.ReadFull(conn, dl); err != nil {
			return errors.New("anytls: failed to read domain length").Base(err)
		}
		domain := make([]byte, dl[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return errors.New("anytls: failed to read domain").Base(err)
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return errors.New("anytls: failed to read port").Base(err)
		}
		dest = xnet.TCPDestination(xnet.DomainAddress(string(domain)), xnet.Port(int(port[0])<<8|int(port[1])))
	case 3:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return errors.New("anytls: failed to read IPv6").Base(err)
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return errors.New("anytls: failed to read port").Base(err)
		}
		dest = xnet.TCPDestination(xnet.IPAddress(ip), xnet.Port(int(port[0])<<8|int(port[1])))
	default:
		return errors.New("anytls: unknown address type")
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})

	ctx2, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx2, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	link, err := dispatcher.Dispatch(ctx2, dest)
	if err != nil {
		return errors.New("failed to dispatch request to ", dest).Base(err)
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx2, requestDonePost, responseDone); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("connection ends").Base(err)
	}
	return nil
}

var _ proxy.UserManager = (*Server)(nil)
