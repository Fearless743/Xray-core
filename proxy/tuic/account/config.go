package account

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	id, err := uuid.ParseString(a.Uuid)
	if err != nil {
		// If not a valid UUID, derive a deterministic UUID from the string (password-as-uuid mode)
		id, err = uuid.ParseString(a.Uuid)
		if err != nil {
			return nil, errors.New("failed to parse TUIC UUID: ", a.Uuid).Base(err)
		}
	}
	password := a.Password
	if password == "" {
		password = a.Uuid // single-credential mode: password == uuid string
	}
	return &MemoryAccount{
		UUID:     id,
		Password: password,
	}, nil
}

type MemoryAccount struct {
	UUID     uuid.UUID
	Password string
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.UUID == account.UUID && a.Password == account.Password
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Uuid:     a.UUID.String(),
		Password: a.Password,
	}
}

func (a *MemoryAccount) IDBytes() [16]byte {
	var id [16]byte
	copy(id[:], a.UUID.Bytes())
	return id
}

type Validator struct {
	emails map[string]struct{}
	users  map[[16]byte]*protocol.MemoryUser
	mutex  sync.RWMutex
}

func NewValidator() *Validator {
	return &Validator{
		emails: make(map[string]struct{}),
		users:  make(map[[16]byte]*protocol.MemoryUser),
	}
}

func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	acct, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("not a TUIC account")
	}
	key := acct.IDBytes()
	if u.Email != "" {
		if _, exists := v.emails[u.Email]; exists {
			// Allow overwrite for hot-reload
			for k, existing := range v.users {
				if existing.Email == u.Email {
					delete(v.users, k)
					break
				}
			}
		}
		v.emails[u.Email] = struct{}{}
	}
	v.users[key] = u
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
	for key, user := range v.users {
		if user.Email == email {
			delete(v.users, key)
			break
		}
	}
	return nil
}

func (v *Validator) Get(id [16]byte) *protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return v.users[id]
}

func (v *Validator) GetPassword(id [16]byte) (string, bool) {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	u := v.users[id]
	if u == nil {
		return "", false
	}
	return u.Account.(*MemoryAccount).Password, true
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	if _, ok := v.emails[email]; !ok {
		return nil
	}
	for _, user := range v.users {
		if user.Email == email {
			return user
		}
	}
	return nil
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, user := range v.users {
		users = append(users, user)
	}
	return users
}

func (v *Validator) GetCount() int64 {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	return int64(len(v.users))
}
