package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trusttunnel"
	"github.com/xtls/xray-core/proxy/trusttunnel/account"
	"google.golang.org/protobuf/proto"
)

type TrustTunnelUserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type TrustTunnelServerConfig struct {
	Users []*TrustTunnelUserConfig `json:"clients"`
}

func (c *TrustTunnelServerConfig) Build() (proto.Message, error) {
	config := &trusttunnel.ServerConfig{}
	for _, user := range c.Users {
		username := user.Username
		if username == "" {
			username = user.Password // Fboard: password field carries UUID
		}
		password := user.Password
		if password == "" {
			password = username
		}
		config.Users = append(config.Users, &protocol.User{
			Level: uint32(user.Level),
			Email: user.Email,
			Account: serial.ToTypedMessage(&account.Account{
				Username: username,
				Password: password,
			}),
		})
	}
	return config, nil
}
