package sudoku

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

type userStoreSnapshot struct {
	// userHash (lowercase hex) -> user
	users map[string]*protocol.MemoryUser
	// email -> userHash
	emailIndex map[string]string
}

func (s *Server) loadStore() *userStoreSnapshot {
	v := s.store.Load()
	if v == nil {
		empty := &userStoreSnapshot{
			users:      make(map[string]*protocol.MemoryUser),
			emailIndex: make(map[string]string),
		}
		s.store.Store(empty)
		return empty
	}
	return v.(*userStoreSnapshot)
}

func (s *Server) lookupUser(userHash string) *protocol.MemoryUser {
	userHash = strings.ToLower(strings.TrimSpace(userHash))
	if userHash == "" {
		return nil
	}
	return s.loadStore().users[userHash]
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	if u == nil || u.Account == nil {
		return errors.New("sudoku: invalid user")
	}
	if _, ok := u.Account.(*MemoryAccount); !ok {
		return errors.New("sudoku: invalid account type")
	}
	s.pendingMu.Lock()
	delete(s.pendingRemoves, u.Email)
	s.pendingAdds[u.Email] = u
	s.pendingMu.Unlock()
	s.scheduleUserUpdate()
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("sudoku: empty email")
	}
	s.pendingMu.Lock()
	delete(s.pendingAdds, email)
	s.pendingRemoves[email] = struct{}{}
	s.pendingMu.Unlock()
	s.scheduleUserUpdate()
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	snap := s.loadStore()
	if h, ok := snap.emailIndex[email]; ok {
		return snap.users[h]
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	snap := s.loadStore()
	users := make([]*protocol.MemoryUser, 0, len(snap.users))
	for _, u := range snap.users {
		users = append(users, u)
	}
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (s *Server) GetUsersCount(ctx context.Context) int64 {
	return int64(len(s.loadStore().users))
}

func (s *Server) scheduleUserUpdate() {
	select {
	case s.updateCh <- struct{}{}:
	default:
	}
}

func (s *Server) userUpdaterLoop() {
	var timer *time.Timer
	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}
		select {
		case <-s.stopCh:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.updateCh:
			if timer == nil {
				timer = time.NewTimer(s.debounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.debounce)
			}
		case <-timerC:
			timer.Stop()
			timer = nil
			s.applyPending()
		}
	}
}

func (s *Server) applyPending() {
	s.pendingMu.Lock()
	adds := s.pendingAdds
	removes := s.pendingRemoves
	s.pendingAdds = make(map[string]*protocol.MemoryUser)
	s.pendingRemoves = make(map[string]struct{})
	s.pendingMu.Unlock()

	if len(adds) == 0 && len(removes) == 0 {
		return
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()

	old := s.loadStore()
	users := make(map[string]*protocol.MemoryUser, len(old.users)+len(adds))
	emailIndex := make(map[string]string, len(old.emailIndex)+len(adds))
	for k, v := range old.users {
		users[k] = v
	}
	for k, v := range old.emailIndex {
		emailIndex[k] = v
	}

	for email := range removes {
		if h, ok := emailIndex[email]; ok {
			delete(users, h)
			delete(emailIndex, email)
		}
	}
	for email, u := range adds {
		acc, ok := u.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		// Drop previous hash for this email if changed.
		if oldH, ok := emailIndex[email]; ok && oldH != acc.UserHash {
			delete(users, oldH)
		}
		users[acc.UserHash] = u
		emailIndex[email] = acc.UserHash
	}

	s.store.Store(&userStoreSnapshot{users: users, emailIndex: emailIndex})
}

// Ensure Server has required fields declared in server.go
var (
	_ = atomic.Value{}
	_ = sync.Mutex{}
)
