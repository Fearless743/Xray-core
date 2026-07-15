package bandwidth

import (
	"sync"

	"github.com/xtls/xray-core/features"
	"golang.org/x/time/rate"
)

// Manager is the interface for per-user bandwidth management.
type Manager interface {
	features.Feature
	// SetUserLimit sets the bandwidth limit for a user in bytes per second.
	// bps is the maximum bytes per second; zero or negative removes the limit.
	SetUserLimit(email string, bytesPerSec int64)
	// SetUserLimiter sets the rate.Limiter for a user.
	// nil limiter means unlimited.
	SetUserLimiter(email string, limiter *rate.Limiter)
	// GetUserLimiter returns the rate.Limiter for a user, or nil if unlimited.
	GetUserLimiter(email string) *rate.Limiter
	// Reset clears all user bandwidth limits.
	Reset()
}

// ManagerType returns the type of the bandwidth manager.
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// Instance is the default Manager implementation.
type Instance struct {
	mu       sync.RWMutex
	limiters map[string]*rate.Limiter
}

// New creates a new bandwidth Manager Instance.
func New() *Instance {
	return &Instance{limiters: make(map[string]*rate.Limiter)}
}

func (*Instance) Type() interface{} { return ManagerType() }
func (*Instance) Start() error      { return nil }
func (*Instance) Close() error      { return nil }

func (m *Instance) SetUserLimit(email string, bytesPerSec int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bytesPerSec <= 0 {
		delete(m.limiters, email)
		return
	}
	if lim, ok := m.limiters[email]; ok {
		lim.SetLimit(rate.Limit(bytesPerSec))
		lim.SetBurst(int(bytesPerSec))
		return
	}
	m.limiters[email] = rate.NewLimiter(rate.Limit(bytesPerSec), int(bytesPerSec))
}

func (m *Instance) SetUserLimiter(email string, limiter *rate.Limiter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limiter == nil {
		delete(m.limiters, email)
		return
	}
	m.limiters[email] = limiter
}

func (m *Instance) GetUserLimiter(email string) *rate.Limiter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.limiters[email]
}

func (m *Instance) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.limiters = make(map[string]*rate.Limiter)
}
