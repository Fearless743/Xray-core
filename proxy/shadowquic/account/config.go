package account

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	name := a.Name
	if name == "" {
		name = a.Password
	}
	password := a.Password
	if password == "" {
		password = a.Name
	}
	return &MemoryAccount{Name: name, Password: password}, nil
}

type MemoryAccount struct {
	Name     string
	Password string
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if o, ok := another.(*MemoryAccount); ok {
		return a.Name == o.Name && a.Password == o.Password
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Name: a.Name, Password: a.Password}
}

// UserEntry is a snapshot for building the JLS user list.
type UserEntry struct {
	Name     string
	Password string
	Email    string
}

type Validator struct {
	emails map[string]struct{}
	users  map[string]*protocol.MemoryUser // key: name
	mutex  sync.RWMutex
}

func NewValidator() *Validator {
	return &Validator{
		emails: make(map[string]struct{}),
		users:  make(map[string]*protocol.MemoryUser),
	}
}

func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	acct, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("not a shadowquic account")
	}
	if u.Email != "" {
		// Allow overwrite for hot-reload by email
		if _, exists := v.emails[u.Email]; exists {
			for k, existing := range v.users {
				if existing.Email == u.Email {
					delete(v.users, k)
					break
				}
			}
		}
		v.emails[u.Email] = struct{}{}
	}
	v.users[acct.Name] = u
	return nil
}

func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if _, ok := v.emails[email]; !ok {
		return errors.New("User ", email, " not found.")
	}
	delete(v.emails, email)
	for k, u := range v.users {
		if u.Email == email {
			delete(v.users, k)
			break
		}
	}
	return nil
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	for _, u := range v.users {
		if u.Email == email {
			return u
		}
	}
	return nil
}

func (v *Validator) GetByName(name string) *protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return v.users[name]
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	out := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, u := range v.users {
		out = append(out, u)
	}
	return out
}

func (v *Validator) GetCount() int64 {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return int64(len(v.users))
}

func (v *Validator) Entries() []UserEntry {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	out := make([]UserEntry, 0, len(v.users))
	for _, u := range v.users {
		acct := u.Account.(*MemoryAccount)
		out = append(out, UserEntry{Name: acct.Name, Password: acct.Password, Email: u.Email})
	}
	return out
}
