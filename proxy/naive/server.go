package naive

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/naive/account"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Server is an inbound connection handler that handles naive HTTP CONNECT proxy protocol.
type Server struct {
	policyManager policy.Manager
	validator     *account.Validator
}

// NewServer creates a new naive inbound handler.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get naive user").Base(err).AtError()
		}
		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}

	v := core.MustFromContext(ctx)
	server := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:     validator,
	}

	return server, nil
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

// Network implements proxy.Inbound.Network().
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.Process().
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	// Read HTTP CONNECT request
	br := bufio.NewReader(conn)

	// Read request line: "CONNECT host:port HTTP/1.1"
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return errors.New("failed to read request line").Base(err)
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")

	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 3 || parts[0] != "CONNECT" {
		return errors.New("invalid request, expected CONNECT")
	}

	target := parts[1]

	// Read headers
	var authHeader string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return errors.New("failed to read header").Base(err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// End of headers
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "authorization:") {
			authHeader = strings.TrimSpace(line[len("authorization:"):])
		}
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	// Validate credentials
	user, err := s.authenticate(authHeader)
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		// Send 407 Proxy Authentication Required
		_, writeErr := conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		if writeErr != nil {
			return errors.New("failed to send auth response").Base(writeErr)
		}
		return err
	}

	// Parse destination host and port
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return errors.New("failed to parse target address").Base(err)
	}

	var port net.Port
	portInt, err := portValue(portStr)
	if err != nil {
		return errors.New("failed to parse port").Base(err)
	}
	port = net.Port(portInt)

	destination := net.TCPDestination(net.ParseAddress(host), port)

	inbound := session.InboundFromContext(ctx)
	inbound.Name = "naive"
	inbound.CanSpliceCopy = 3
	inbound.User = user
	sessionPolicy = s.policyManager.ForLevel(user.Level)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})

	errors.LogInfo(ctx, "received request for ", destination)

	// Send 200 Connection Established
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return errors.New("failed to send 200 response").Base(err)
	}

	// Create a combined reader that uses buffered data first, then the connection directly
	// We need to use the buffered reader as the source since some data may already be buffered
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		// Write buffered data to pipe
		_, err := io.Copy(pipeWriter, br)
		if err != nil {
			pipeWriter.CloseWithError(err)
			return
		}
		pipeWriter.Close()
	}()

	// Use a multi-source reader that reads from pipe first, then from conn
	combinedReader := io.MultiReader(pipeReader, conn)

	return s.handleConnection(ctx, sessionPolicy, destination, buf.NewReader(combinedReader), buf.NewWriter(conn), dispatcher)
}

// authenticate validates the Authorization header and returns the user if valid.
func (s *Server) authenticate(authHeader string) (*protocol.MemoryUser, error) {
	if authHeader == "" {
		return nil, errors.New("missing authorization header")
	}

	// Expect "Basic base64encoded"
	if !strings.HasPrefix(authHeader, "Basic ") {
		return nil, errors.New("unsupported auth type, expected Basic")
	}

	encoded := strings.TrimSpace(authHeader[6:])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("failed to decode base64 auth").Base(err)
	}

	credentials := string(decoded)
	colonIdx := strings.IndexByte(credentials, ':')
	if colonIdx == -1 {
		return nil, errors.New("invalid auth format, expected user:password")
	}

	password := credentials[colonIdx+1:]
	user := s.validator.Get(password)
	if user == nil {
		return nil, errors.New("invalid user")
	}

	return user, nil
}

// portValue parses a port string to uint16.
func portValue(s string) (uint16, error) {
	var p uint16
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid port")
		}
		p = p*10 + uint16(c-'0')
	}
	return p, nil
}

func (s *Server) handleConnection(ctx context.Context, sessionPolicy policy.Session,
	destination net.Destination,
	clientReader buf.Reader,
	clientWriter buf.Writer, dispatcher routing.Dispatcher,
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
		if err := buf.Copy(clientReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transfer request").Base(err)
		}
		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(link.Reader, clientWriter, buf.UpdateActivity(timer)); err != nil {
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
