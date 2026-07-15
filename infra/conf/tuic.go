package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/tuic"
	"github.com/xtls/xray-core/proxy/tuic/account"
	"google.golang.org/protobuf/proto"
)

type TUICUserConfig struct {
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
		config.Users = append(config.Users, &protocol.User{
			Level: uint32(user.Level),
			Email: user.Email,
			Account: serial.ToTypedMessage(&account.Account{
				Password: user.Password,
			}),
		})
	}
	return config, nil
}
