package sudoku

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

// MemoryAccount is the runtime account for a Sudoku client.
// UserHash is hex(sha256(decoded_private_key_bytes)[:8]) — 16 hex chars.
type MemoryAccount struct {
	PrivateKey string
	UserHash   string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	hash := strings.ToLower(strings.TrimSpace(a.UserHash))
	priv := strings.TrimSpace(a.PrivateKey)
	if hash == "" {
		if priv == "" {
			return nil, errors.New("sudoku: account requires private_key or user_hash")
		}
		h, err := UserHashFromPrivateKeyHex(priv)
		if err != nil {
			return nil, err
		}
		hash = h
	}
	return &MemoryAccount{PrivateKey: priv, UserHash: hash}, nil
}

func (m *MemoryAccount) Equals(another protocol.Account) bool {
	if o, ok := another.(*MemoryAccount); ok {
		return m.UserHash == o.UserHash
	}
	return false
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{PrivateKey: m.PrivateKey, UserHash: m.UserHash}
}

// UserHashFromPrivateKeyHex computes the wire UserHash for a client key hex string.
// Official clients decode the hex key first, then sha256(raw_bytes)[:8].
func UserHashFromPrivateKeyHex(keyHex string) (string, error) {
	keyHex = strings.TrimSpace(keyHex)
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", errors.New("sudoku: invalid private_key hex").Base(err)
	}
	if len(raw) == 0 {
		return "", errors.New("sudoku: empty private_key")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8]), nil
}
