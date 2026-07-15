package bandwidth

import (
	"github.com/xtls/xray-core/features"
	"golang.org/x/time/rate"
)

// ManagerType returns the type of the bandwidth manager.
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// Manager is the interface for per-user bandwidth management.
type Manager interface {
	features.Feature

	// Reset clears all user bandwidth limits.
	Reset()

	// SetUserLimit sets the bandwidth limit for a user in bytes per second.
	// bps is the maximum bytes per second.
	SetUserLimit(email string, bps int64)

	// SetUserLimiter sets the rate.Limiter for a user.
	// nil limiter means unlimited.
	SetUserLimiter(email string, limiter *rate.Limiter)
}
