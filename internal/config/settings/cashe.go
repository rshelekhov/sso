package settings

import (
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	redisStorage "github.com/rshelekhov/sso/pkg/storage/redis"
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

func ToRedisConfig(p RedisParams) storage.RedisConfig {
	return storage.RedisConfig{
		Redis: &redisStorage.Config{
			Host:         p.Host,
			Port:         p.Port,
			Password:     p.Password,
			DB:           p.DB,
			PoolSize:     p.PoolSize,
			MinIdleConns: p.MinIdleConns,
		},
		SessionTTL:      p.SessionTTL,
		RevokedTokenTTL: p.RevokedTokenTTL,
	}
}
