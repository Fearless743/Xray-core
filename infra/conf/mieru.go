package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/mieru"
	"github.com/xtls/xray-core/proxy/mieru/account"
	"google.golang.org/protobuf/proto"
)

type MieruUserConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type MieruServerConfig struct {
	Users          []*MieruUserConfig `json:"clients"`
	Transport      string             `json:"transport"`
	TrafficPattern string             `json:"traffic_pattern"`
}

func (c *MieruServerConfig) Build() (proto.Message, error) {
	config := &mieru.ServerConfig{
		Transport:      c.Transport,
		TrafficPattern: c.TrafficPattern,
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
