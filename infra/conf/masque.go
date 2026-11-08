package conf

import (
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/masque"
	"github.com/xtls/xray-core/proxy/masque/account"
	"google.golang.org/protobuf/proto"
)

type MASQUEUserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type MASQUEServerConfig struct {
	Users           []*MASQUEUserConfig `json:"clients"`
	Addresses       []string            `json:"addresses"`
	AdvertiseRoutes []string            `json:"advertise_routes"`
	MTU             uint32              `json:"mtu"`
}

func (c *MASQUEServerConfig) Build() (proto.Message, error) {
	config := &masque.ServerConfig{
		Addresses:       c.Addresses,
		AdvertiseRoutes: c.AdvertiseRoutes,
		Mtu:             c.MTU,
	}
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
