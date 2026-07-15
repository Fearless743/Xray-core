package bandwidth

import (
	"testing"

	"golang.org/x/time/rate"
)

func TestInstanceSetGetReset(t *testing.T) {
	m := New()
	if got := m.GetUserLimiter("user@example.com"); got != nil {
		t.Fatal("expected nil limiter before set")
	}
	m.SetUserLimit("user@example.com", 1024)
	if got := m.GetUserLimiter("user@example.com"); got == nil {
		t.Fatal("expected limiter after set")
	}
	m.SetUserLimit("user@example.com", 0)
	if got := m.GetUserLimiter("user@example.com"); got != nil {
		t.Fatal("expected limiter removal on zero speed")
	}
	m.SetUserLimit("user@example.com", 2048)
	m.Reset()
	if got := m.GetUserLimiter("user@example.com"); got != nil {
		t.Fatal("expected reset to clear limiters")
	}
}

func TestInstanceSetUserLimiter(t *testing.T) {
	m := New()
	lim := rate.NewLimiter(123, 123)
	m.SetUserLimiter("user@example.com", lim)
	if got := m.GetUserLimiter("user@example.com"); got != lim {
		t.Fatal("expected shared limiter to be preserved")
	}
}
