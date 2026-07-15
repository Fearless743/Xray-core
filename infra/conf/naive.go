package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/naive"
	"github.com/xtls/xray-core/proxy/naive/account"
	"google.golang.org/protobuf/proto"
)

type NaiveUserConfig struct {
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type NaiveServerConfig struct {
	Users []*NaiveUserConfig `json:"accounts"`
}

func (c *NaiveServerConfig) Build() (proto.Message, error) {
	config := &naive.ServerConfig{}
	for _, user := range c.Users {
		password := user.Pass
		if password == "" {
			password = user.Password
		}
		config.Users = append(config.Users, &protocol.User{
			Level: uint32(user.Level),
			Email: user.Email,
			Account: serial.ToTypedMessage(&account.Account{
				Password: password,
			}),
		})
	}
	return config, nil
}
