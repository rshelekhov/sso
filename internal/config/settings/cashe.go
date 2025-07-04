package settings

import (
	"time"
)

type Cache struct {
	Redis RedisParams `yaml:"Redis"`
}

type RedisParams struct {
	Host            string        `yaml:"Host"`
	Port            int           `yaml:"Port"`
	Password        string        `yaml:"Password"`
	DB              int           `yaml:"DB"`
	PoolSize        int           `yaml:"PoolSize" default:"10"`
	MinIdleConns    int           `yaml:"MinIdleConns" default:"5"`
	SessionTTL      time.Duration `yaml:"SessionTTL" default:"24h"`
	RevokedTokenTTL time.Duration `yaml:"RevokedTokenTTL" default:"24h"`
}
