// Vendored/adapted from github.com/apernet/hysteria app/cmd/server.go realmServerRuntime
// Upstream commit: ff1eec4b68dab3d1377b6b11bdd1be2180b0ff26
// License: MIT (apernet/hysteria)
//
package realm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultSTUNServers matches official Hysteria Realms defaults.
var DefaultSTUNServers = []string{
	"stun.nextcloud.com:3478",
	"stun.sip.us:3478",
	"global.stun.twilio.com:3478",
}

const connectSTUNCacheTTL = 10 * time.Second

// RuntimeConfig tunes the server-side Realms registration loop.
// Zero values use sensible defaults (aligned with official hysteria).
type RuntimeConfig struct {
	STUNServers       []string
	STUNTimeout       time.Duration
	PunchTimeout      time.Duration
	HeartbeatInterval time.Duration
	// Insecure skips TLS verification for the rendezvous HTTPS client only.
	Insecure bool
	// Family restricts STUN/punch address families (Any/IPv4/IPv6).
	Family AddrFamily
}

// ServerRuntime keeps a realm registered and responds to punch events.
type ServerRuntime struct {
	cancel      context.CancelFunc
	client      *Client
	realmID     string
	punchConn   *PunchPacketConn
	stunServers []string
	puncher     *ServerPuncher
	config      RuntimeConfig
	family      AddrFamily

	mu      sync.Mutex
	session session
	addrs   []netip.AddrPort
	addrsAt time.Time

	connectSF singleflight.Group
}

type session struct {
	id  string
	ttl int
}

var (
	errSessionInvalid = errors.New("realm session invalid")
	errSessionLost    = errors.New("realm session lost")
)

// StartServerRuntime binds the realm registration loop to punchConn.
// On success the realm is already registered once; a background goroutine
// maintains heartbeat/SSE and re-registers on session loss.
// Caller must Close() the returned runtime (typically from Listener.Close).
func StartServerRuntime(parent context.Context, addr *Addr, punchConn *PunchPacketConn, cfg RuntimeConfig) (*ServerRuntime, error) {
	if addr == nil {
		return nil, errors.New("realm addr is nil")
	}
	if punchConn == nil {
		return nil, errors.New("punch conn is nil")
	}

	stunServers := pickSTUNServers(addr, cfg.STUNServers)
	httpClient := realmHTTPClient(cfg.Insecure)
	rClient, err := NewClientFromAddr(addr, httpClient)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	puncher, err := NewServerPuncher(ctx, punchConn)
	if err != nil {
		cancel()
		return nil, err
	}

	rt := &ServerRuntime{
		cancel:      cancel,
		client:      rClient,
		realmID:     addr.RealmID,
		punchConn:   punchConn,
		stunServers: stunServers,
		puncher:     puncher,
		config:      cfg,
		family:      cfg.Family,
	}

	// Initial STUN must use the raw socket (before QUIC starts demuxing).
	if _, _, err := rt.refreshAddrsDirect(ctx); err != nil {
		cancel()
		return nil, err
	}
	initial, err := rt.register(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	rt.setSession(initial)
	go rt.run(ctx, initial)
	return rt, nil
}

func pickSTUNServers(addr *Addr, override []string) []string {
	if addr != nil {
		if stunServers := addr.Params["stun"]; len(stunServers) > 0 {
			return append([]string(nil), stunServers...)
		}
	}
	if len(override) > 0 {
		return append([]string(nil), override...)
	}
	return append([]string(nil), DefaultSTUNServers...)
}

func realmHTTPClient(insecure bool) *http.Client {
	if !insecure {
		return nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for self-signed rendezvous
	return &http.Client{Transport: tr}
}

func (r *ServerRuntime) run(ctx context.Context, sess session) {
	for ctx.Err() == nil {
		if err := r.runSession(ctx, sess); err != nil && ctx.Err() == nil {
			// session lost — re-register below
		}
		sess = r.registerWithBackoff(ctx)
		if sess.id == "" {
			return
		}
	}
}

func (r *ServerRuntime) registerWithBackoff(ctx context.Context) session {
	backoff := time.Second
	for ctx.Err() == nil {
		if _, _, err := r.refreshAddrs(ctx); err != nil {
			// continue with last-known addrs
		}
		sess, err := r.register(ctx)
		if err == nil {
			r.setSession(sess)
			return sess
		}
		if isRegisterFatal(err) {
			return session{}
		}
		if !sleepContext(ctx, backoff) {
			return session{}
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	return session{}
}

func (r *ServerRuntime) register(ctx context.Context) (session, error) {
	localAddrs := r.currentAddrs()
	registerResp, err := r.client.Register(ctx, r.realmID, addrPortStrings(localAddrs))
	if err != nil {
		return session{}, err
	}
	return session{id: registerResp.SessionID, ttl: registerResp.TTL}, nil
}

func (r *ServerRuntime) runSession(ctx context.Context, sess session) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- r.heartbeatLoop(sessionCtx, sess) }()
	go func() { errCh <- r.eventsLoop(sessionCtx, sess) }()
	err := <-errCh
	cancel()
	return err
}

func (r *ServerRuntime) heartbeatLoop(ctx context.Context, sess session) error {
	interval := r.config.HeartbeatInterval
	if interval == 0 {
		interval = sessionTTLDuration(sess.ttl) / 2
		if interval <= 0 {
			interval = 15 * time.Second
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	lastOK := time.Now()
	lastPublished := r.currentAddrs()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			req := HeartbeatRequest{}
			if current := r.currentAddrs(); !slices.Equal(current, lastPublished) {
				req.Addresses = addrPortStrings(current)
				lastPublished = current
			}
			resp, err := r.client.Heartbeat(ctx, r.realmID, sess.id, req)
			if err != nil {
				if isSessionInvalid(err) {
					return errSessionInvalid
				}
				if time.Since(lastOK) > sessionTTLDuration(sess.ttl) {
					return errSessionLost
				}
				continue
			}
			lastOK = time.Now()
			if r.config.HeartbeatInterval == 0 && resp.TTL > 0 {
				next := time.Duration(resp.TTL) * time.Second / 2
				if next > 0 && next != interval {
					interval = next
					t.Reset(interval)
				}
			}
		}
	}
}

func (r *ServerRuntime) eventsLoop(ctx context.Context, sess session) error {
	backoff := time.Second
	lastOK := time.Now()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stream, err := r.client.Events(ctx, r.realmID, sess.id)
		if err != nil {
			if isSessionInvalid(err) {
				return errSessionInvalid
			}
			if time.Since(lastOK) > sessionTTLDuration(sess.ttl) {
				return errSessionLost
			}
			if !sleepContext(ctx, backoff) {
				return ctx.Err()
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		lastOK = time.Now()
		backoff = time.Second
		for {
			ev, err := stream.Next()
			if err != nil {
				_ = stream.Close()
				break
			}
			lastOK = time.Now()
			go r.respond(ctx, ev)
		}
	}
}

func (r *ServerRuntime) connectAddrs(ctx context.Context) ([]netip.AddrPort, error) {
	if cached := r.cachedAddrs(); cached != nil {
		return cached, nil
	}
	v, err, _ := r.connectSF.Do("stun", func() (any, error) {
		if cached := r.cachedAddrs(); cached != nil {
			return cached, nil
		}
		addrs, _, err := r.refreshAddrs(ctx)
		if err != nil {
			return nil, err
		}
		return addrs, nil
	})
	if err != nil {
		if fallback := r.currentAddrs(); len(fallback) > 0 {
			return fallback, err
		}
		return nil, err
	}
	return v.([]netip.AddrPort), nil
}

func (r *ServerRuntime) cachedAddrs() []netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addrs == nil || time.Since(r.addrsAt) >= connectSTUNCacheTTL {
		return nil
	}
	return append([]netip.AddrPort(nil), r.addrs...)
}

func (r *ServerRuntime) respond(ctx context.Context, ev *PunchEvent) {
	if ev == nil {
		return
	}
	peerAddrs, err := parseAddrPorts(ev.Addresses)
	if err != nil {
		return
	}

	freshAddrs, _ := r.connectAddrs(ctx)

	if sess := r.currentSession(); sess.id != "" && len(freshAddrs) > 0 {
		postCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		_ = r.client.ConnectResponse(postCtx, r.realmID, sess.id, ev.Nonce, addrPortStrings(freshAddrs))
		cancel()
	}

	_, _ = r.puncher.Respond(ctx, ev.Nonce, freshAddrs, peerAddrs, ev.PunchMetadata, PunchConfig{
		Timeout: r.config.PunchTimeout,
		Family:  r.family,
	})
}

// Close cancels the runtime and attempts to deregister the realm.
func (r *ServerRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.cancel()
	sess := r.currentSession()
	if sess.id == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return r.client.Deregister(ctx, r.realmID, sess.id)
}

func (r *ServerRuntime) setSession(sess session) {
	r.mu.Lock()
	r.session = sess
	r.mu.Unlock()
}

func (r *ServerRuntime) currentSession() session {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.session
}

func (r *ServerRuntime) refreshAddrs(ctx context.Context) ([]netip.AddrPort, bool, error) {
	return r.refreshAddrsWith(ctx, func(ctx context.Context, config STUNConfig) ([]netip.AddrPort, error) {
		return DiscoverWithDemux(ctx, r.punchConn, config)
	})
}

func (r *ServerRuntime) refreshAddrsDirect(ctx context.Context) ([]netip.AddrPort, bool, error) {
	return r.refreshAddrsWith(ctx, func(ctx context.Context, config STUNConfig) ([]netip.AddrPort, error) {
		return Discover(ctx, r.punchConn.PacketConn, config)
	})
}

func (r *ServerRuntime) refreshAddrsWith(ctx context.Context, discover func(context.Context, STUNConfig) ([]netip.AddrPort, error)) ([]netip.AddrPort, bool, error) {
	addrs, err := discover(ctx, STUNConfig{
		Servers: r.stunServers,
		Timeout: r.config.STUNTimeout,
		Family:  r.family,
	})
	if err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	changed := !slices.Equal(r.addrs, addrs)
	if changed {
		r.addrs = append([]netip.AddrPort(nil), addrs...)
	}
	r.addrsAt = time.Now()
	current := append([]netip.AddrPort(nil), r.addrs...)
	r.mu.Unlock()
	return current, changed, nil
}

func (r *ServerRuntime) currentAddrs() []netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netip.AddrPort(nil), r.addrs...)
}

// LocalAddr returns the underlying UDP local address if available.
func (r *ServerRuntime) LocalAddr() net.Addr {
	if r == nil || r.punchConn == nil {
		return nil
	}
	return r.punchConn.LocalAddr()
}

func sessionTTLDuration(ttl int) time.Duration {
	if ttl <= 0 {
		return time.Minute
	}
	return time.Duration(ttl) * time.Second
}

func isSessionInvalid(err error) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) &&
		(statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusNotFound)
}

func isRegisterFatal(err error) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusBadRequest
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func addrPortStrings(addrs []netip.AddrPort) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func parseAddrPorts(addrs []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, s := range addrs {
		addr, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}
