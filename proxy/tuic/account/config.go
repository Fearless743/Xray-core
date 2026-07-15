package account

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"

	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	return &MemoryAccount{
		Password: a.Password,
	}, nil
}

type MemoryAccount struct {
	Password string
}

func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Password == account.Password
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Password: a.Password,
	}
}

type Validator struct {
	emails map[string]struct{}
	users  map[string]*protocol.MemoryUser
	mutex  sync.Mutex
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

	if u.Email != "" {
		if _, ok := v.emails[u.Email]; ok {
			return errors.New("User ", u.Email, " already exists.")
		}
		v.emails[u.Email] = struct{}{}
	}
	acct := u.Account.(*MemoryAccount)
	v.users[acct.Password] = u
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

func (v *Validator) Get(password string) *protocol.MemoryUser {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return v.users[password]
}

func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if _, ok := v.emails[email]; ok {
		for _, user := range v.users {
			if user.Email == email {
				return user
			}
		}
	}
	return nil
}

func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	users := make([]*protocol.MemoryUser, 0, len(v.users))
	for _, user := range v.users {
		users = append(users, user)
	}
	return users
}

func (v *Validator) GetCount() int64 {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return int64(len(v.users))
}
