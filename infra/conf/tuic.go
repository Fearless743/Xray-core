package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/tuic"
	"github.com/xtls/xray-core/proxy/tuic/account"
	"google.golang.org/protobuf/proto"
)

type TUICUserConfig struct {
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type TUICServerConfig struct {
	Users             []*TUICUserConfig `json:"clients"`
	CongestionControl string            `json:"congestion_control"`
}

func (c *TUICServerConfig) Build() (proto.Message, error) {
	config := &tuic.ServerConfig{
		CongestionControl: c.CongestionControl,
	}
	for _, user := range c.Users {
		uuid := user.UUID
		if uuid == "" {
			uuid = user.Password // Fboard: password field carries UUID
		}
		password := user.Password
		if password == "" {
			password = uuid
		}
		config.Users = append(config.Users, &protocol.User{
			Level: uint32(user.Level),
			Email: user.Email,
			Account: serial.ToTypedMessage(&account.Account{
				Uuid:     uuid,
				Password: password,
			}),
		})
	}
	return config, nil
}
