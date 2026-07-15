package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

type AnyTLSUserConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type AnyTLSServerConfig struct {
	Users         []*AnyTLSUserConfig `json:"clients"`
	PaddingScheme string              `json:"padding_scheme"`
}

func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	config := &anytls.ServerConfig{
		PaddingScheme: c.PaddingScheme,
	}
	for _, user := range c.Users {
		config.Users = append(config.Users, &protocol.User{
			Level: uint32(user.Level),
			Email: user.Email,
			Account: serial.ToTypedMessage(&anytls.Account{
				Password: user.Password,
			}),
		})
	}
	return config, nil
}
