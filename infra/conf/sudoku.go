package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/sudoku"
	"google.golang.org/protobuf/proto"
)

type SudokuUserConfig struct {
	PrivateKey string `json:"private_key"`
	UserHash   string `json:"user_hash"`
	Password   string `json:"password"` // alias: treated as private_key when private_key empty
	Level      byte   `json:"level"`
	Email      string `json:"email"`
}

type SudokuServerConfig struct {
	Users              []*SudokuUserConfig `json:"clients"`
	Key                string              `json:"key"`
	AEADMethod         string              `json:"aead_method"`
	PaddingMin         uint32              `json:"padding_min"`
	PaddingMax         uint32              `json:"padding_max"`
	TableType          string              `json:"table_type"`
	EnablePureDownlink *bool               `json:"enable_pure_downlink"`
	CustomTable        string              `json:"custom_table"`
	CustomTables       []string            `json:"custom_tables"`
	HandshakeTimeout   uint32              `json:"handshake_timeout"`
	DisableHTTPMask    bool                `json:"disable_http_mask"`
	HTTPMaskMode       string              `json:"http_mask_mode"`
	PathRoot           string              `json:"path_root"`
	Fallback           string              `json:"fallback"`
	Multiplex          string              `json:"multiplex"`
}

func (c *SudokuServerConfig) Build() (proto.Message, error) {
	pure := true
	if c.EnablePureDownlink != nil {
		pure = *c.EnablePureDownlink
	}
	config := &sudoku.ServerConfig{
		Key:                c.Key,
		AeadMethod:         c.AEADMethod,
		PaddingMin:         c.PaddingMin,
		PaddingMax:         c.PaddingMax,
		TableType:          c.TableType,
		EnablePureDownlink: pure,
		CustomTable:        c.CustomTable,
		CustomTables:       c.CustomTables,
		HandshakeTimeout:   c.HandshakeTimeout,
		DisableHttpMask:    c.DisableHTTPMask,
		HttpMaskMode:       c.HTTPMaskMode,
		PathRoot:           c.PathRoot,
		Fallback:           c.Fallback,
		Multiplex:          c.Multiplex,
	}
	for _, user := range c.Users {
		priv := user.PrivateKey
		if priv == "" {
			priv = user.Password
		}
		config.Users = append(config.Users, &protocol.User{
			Level: uint32(user.Level),
			Email: user.Email,
			Account: serial.ToTypedMessage(&sudoku.Account{
				PrivateKey: priv,
				UserHash:   user.UserHash,
			}),
		})
	}
	return config, nil
}
