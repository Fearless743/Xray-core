package sudoku

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/buf"
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
	sudokucfg "github.com/xtls/xray-core/proxy/sudoku/config"
	"github.com/xtls/xray-core/proxy/sudoku/handler"
	"github.com/xtls/xray-core/proxy/sudoku/obfs/httpmask"
	sudokuobfs "github.com/xtls/xray-core/proxy/sudoku/obfs/sudoku"
	sudokuprotocol "github.com/xtls/xray-core/proxy/sudoku/protocol"
	"github.com/xtls/xray-core/proxy/sudoku/tunnel"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const protocolName = "sudoku"

// Server is an Xray inbound implementing the official Sudoku protocol.
type Server struct {
	policyManager policy.Manager
	protoCfg      *sudokucfg.Config
	tables        []*sudokuobfs.Table
	tunnelSrv     *httpmask.TunnelServer
	fallback      string

	store          atomic.Value // *userStoreSnapshot
	wmu            sync.Mutex
	pendingAdds    map[string]*protocol.MemoryUser
	pendingRemoves map[string]struct{}
	pendingMu      sync.Mutex
	updateCh       chan struct{}
	stopCh         chan struct{}
	debounce       time.Duration
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, xerrors.New("sudoku: nil config")
	}
	key := strings.TrimSpace(config.Key)
	if key == "" {
		return nil, xerrors.New("sudoku: server key is required")
	}

	aead := strings.TrimSpace(config.AeadMethod)
	if aead == "" {
		aead = "chacha20-poly1305"
	}
	tableType := strings.TrimSpace(config.TableType)
	if tableType == "" {
		tableType = "prefer_entropy"
	}
	httpMode := strings.TrimSpace(config.HttpMaskMode)
	if httpMode == "" {
		httpMode = "legacy"
	}
	paddingMin := int(config.PaddingMin)
	paddingMax := int(config.PaddingMax)
	if paddingMax == 0 && paddingMin == 0 {
		paddingMin, paddingMax = 5, 15
	}
	if paddingMax < paddingMin {
		paddingMax = paddingMin
	}
	hsTimeout := int(config.HandshakeTimeout)
	if hsTimeout <= 0 {
		hsTimeout = 5
	}
	multiplex := strings.TrimSpace(config.Multiplex)
	if multiplex == "" {
		multiplex = "off"
	}

	protoCfg := &sudokucfg.Config{
		Mode:               "server",
		Transport:          "tcp",
		Key:                key,
		AEAD:               aead,
		PaddingMin:         paddingMin,
		PaddingMax:         paddingMax,
		ASCII:              tableType,
		CustomTable:        config.CustomTable,
		CustomTables:       append([]string(nil), config.CustomTables...),
		EnablePureDownlink: config.EnablePureDownlink,
		Multiplex:          multiplex,
		FallbackAddr:       strings.TrimSpace(config.Fallback),
		SuspiciousAction:   "fallback",
		HTTPMask: sudokucfg.HTTPMaskConfig{
			Disable:  config.DisableHttpMask,
			Mode:     httpMode,
			PathRoot: strings.TrimSpace(config.PathRoot),
		},
	}
	if protoCfg.FallbackAddr == "" {
		protoCfg.SuspiciousAction = "silent"
	}

	tables, err := buildServerTables(protoCfg)
	if err != nil {
		return nil, xerrors.New("sudoku: build tables").Base(err)
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager:  v.GetFeature(policy.ManagerType()).(policy.Manager),
		protoCfg:       protoCfg,
		tables:         tables,
		fallback:       protoCfg.FallbackAddr,
		updateCh:       make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		debounce:       200 * time.Millisecond,
		pendingAdds:    make(map[string]*protocol.MemoryUser),
		pendingRemoves: make(map[string]struct{}),
	}

	users := make(map[string]*protocol.MemoryUser)
	emailIndex := make(map[string]string)
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, xerrors.New("sudoku: bad user").Base(err)
		}
		acc, ok := mu.Account.(*MemoryAccount)
		if !ok {
			return nil, xerrors.New("sudoku: user account type")
		}
		users[acc.UserHash] = mu
		emailIndex[mu.Email] = acc.UserHash
	}
	s.store.Store(&userStoreSnapshot{users: users, emailIndex: emailIndex})

	if protoCfg.HTTPMaskTunnelEnabled() {
		s.tunnelSrv = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
			Mode:     protoCfg.HTTPMask.Mode,
			PathRoot: protoCfg.HTTPMask.PathRoot,
			AuthKey:  protoCfg.Key,
			EarlyHandshake: tunnel.NewHTTPMaskServerEarlyHandshake(tunnel.EarlyCodecConfig{
				PSK:                protoCfg.Key,
				AEAD:               protoCfg.AEAD,
				EnablePureDownlink: protoCfg.EnablePureDownlink,
				PaddingMin:         protoCfg.PaddingMin,
				PaddingMax:         protoCfg.PaddingMax,
			}, tables, tunnel.AllowHandshakeReplay),
			PassThroughOnReject: protoCfg.FallbackAddr != "" || protoCfg.SuspiciousAction == "silent",
		})
	}

	go s.userUpdaterLoop()
	return s, nil
}

func buildServerTables(cfg *sudokucfg.Config) ([]*sudokuobfs.Table, error) {
	patterns := cfg.CustomTables
	if len(patterns) == 0 && strings.TrimSpace(cfg.CustomTable) != "" {
		patterns = []string{cfg.CustomTable}
	}
	if len(patterns) == 0 {
		patterns = []string{""}
	}
	// Match official server convenience: for entropy uplink, also accept default table.
	if len(patterns) > 0 && strings.TrimSpace(patterns[0]) != "" {
		asciiMode, err := sudokuobfs.ParseASCIIMode(cfg.ASCII)
		if err != nil {
			return nil, err
		}
		if asciiMode.Uplink == "entropy" {
			patterns = append([]string{""}, patterns...)
		}
	}
	tableSet, err := sudokuobfs.NewTableSet(cfg.Key, cfg.ASCII, patterns)
	if err != nil {
		return nil, err
	}
	return tableSet.Candidates(), nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UNIX}
}

// Process implements proxy.Inbound.Process().
func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessPol := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPol.Timeouts.Handshake))

	rawConn := net.Conn(conn)
	handshakeConn := rawConn
	cfg := s.protoCfg
	allowFallback := true

	if s.tunnelSrv != nil {
		res, c, err := s.tunnelSrv.HandleConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return xerrors.New("sudoku: httpmask prelude").Base(err)
		}
		switch res {
		case httpmask.HandleDone:
			return nil
		case httpmask.HandleStartTunnel:
			// Already past HTTPMask; disable mask for remaining handshake path.
			inner := *cfg
			inner.HTTPMask.Disable = true
			cfg = &inner
			handshakeConn = c
			allowFallback = false
		case httpmask.HandlePassThrough:
			if r, ok := c.(interface{ IsHTTPMaskRejected() bool }); ok && r.IsHTTPMaskRejected() {
				handler.HandleSuspicious(c, rawConn, cfg)
				return nil
			}
			handshakeConn = c
		default:
			_ = rawConn.Close()
			return xerrors.New("sudoku: unexpected httpmask result")
		}
	}

	tunnelConn, meta, err := tunnel.HandshakeAndUpgradeWithTablesMeta(handshakeConn, cfg, s.tables)
	if err != nil {
		if susp, ok := err.(*tunnel.SuspiciousError); ok {
			if allowFallback {
				handler.HandleSuspicious(susp.Conn, handshakeConn, cfg)
				return nil
			}
			_ = rawConn.Close()
			return xerrors.New("sudoku: suspicious handshake").Base(susp.Err)
		}
		_ = rawConn.Close()
		return xerrors.New("sudoku: handshake").Base(err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	userHash := ""
	if meta != nil {
		userHash = strings.ToLower(strings.TrimSpace(meta.UserHash))
	}
	user := s.lookupUser(userHash)
	if user == nil {
		_ = tunnelConn.Close()
		return xerrors.New("sudoku: unauthorized user_hash=", userHash)
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{}
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.Name = protocolName
	inbound.User = user
	inbound.CanSpliceCopy = 3

	// First KIP control message selects session type.
	var msg *tunnel.KIPMessage
	for {
		m, err := tunnel.ReadKIPMessage(tunnelConn)
		if err != nil {
			_ = tunnelConn.Close()
			return xerrors.New("sudoku: read kip").Base(err)
		}
		if m.Type == tunnel.KIPTypeKeepAlive {
			continue
		}
		msg = m
		break
	}

	switch msg.Type {
	case tunnel.KIPTypeStartUoT:
		// UDP-over-TCP: first version dials system UDP (stats still attribute to user via inbound).
		return tunnel.HandleUoTServer(tunnelConn)
	case tunnel.KIPTypeStartMux:
		return tunnel.HandleMuxWithDialer(tunnelConn, nil, func(targetAddr string) (net.Conn, error) {
			return s.dialViaDispatcher(ctx, user, targetAddr, dispatcher)
		})
	case tunnel.KIPTypeStartRev:
		_ = tunnelConn.Close()
		return xerrors.New("sudoku: reverse proxy sessions are not supported in Xray inbound")
	case tunnel.KIPTypeOpenTCP:
		destAddrStr, _, _, err := sudokuprotocol.ReadAddress(bytes.NewReader(msg.Payload))
		if err != nil {
			_ = tunnelConn.Close()
			return xerrors.New("sudoku: bad target").Base(err)
		}
		return s.relayTCP(ctx, user, destAddrStr, tunnelConn, dispatcher)
	default:
		_ = tunnelConn.Close()
		return xerrors.New("sudoku: unknown kip type ", msg.Type)
	}
}

func (s *Server) dialViaDispatcher(ctx context.Context, user *protocol.MemoryUser, targetAddr string, dispatcher routing.Dispatcher) (net.Conn, error) {
	dest, err := parseDestination(targetAddr)
	if err != nil {
		return nil, err
	}
	out, in := net.Pipe()
	go func() {
		_ = s.relayTCP(ctx, user, targetAddr, in, dispatcher)
		_ = in.Close()
	}()
	// Wait briefly so Dispatch failures surface as immediate close; pipe still works if slow.
	_ = dest
	return out, nil
}

func (s *Server) relayTCP(ctx context.Context, user *protocol.MemoryUser, targetAddr string, client net.Conn, dispatcher routing.Dispatcher) error {
	dest, err := parseDestination(targetAddr)
	if err != nil {
		_ = client.Close()
		return err
	}

	level := uint32(0)
	email := ""
	if user != nil {
		level = user.Level
		email = user.Email
	}
	sessPol := s.policyManager.ForLevel(level)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   client.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  email,
	})

	// Clone inbound user into this stream context.
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{Name: protocolName, User: user, CanSpliceCopy: 3}
		ctx = session.ContextWithInbound(ctx, inbound)
	} else {
		inbound.User = user
		inbound.Name = protocolName
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPol.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessPol.Buffer)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		_ = client.Close()
		return xerrors.New("sudoku: dispatch ", dest).Base(err)
	}

	clientReader := buf.NewReader(client)
	clientWriter := buf.NewWriter(client)

	requestDone := func() error {
		defer timer.SetTimeout(sessPol.Timeouts.DownlinkOnly)
		return buf.Copy(clientReader, link.Writer, buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessPol.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, clientWriter, buf.UpdateActivity(timer))
	}
	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		return xerrors.New("sudoku: connection ends").Base(err)
	}
	return nil
}

func parseDestination(addr string) (xnet.Destination, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return xnet.Destination{}, err
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return xnet.Destination{}, err
	}
	return xnet.TCPDestination(xnet.ParseAddress(host), port), nil
}

// Close stops the user updater loop.
func (s *Server) Close() error {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	return nil
}

var (
	_ proxy.UserManager = (*Server)(nil)
	_ proxy.Inbound     = (*Server)(nil)
	_                   = io.EOF
	_                   = errors.New
)
