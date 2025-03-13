package settings

import (
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	redisStorage "github.com/rshelekhov/sso/pkg/storage/redis"
)

type Cache struct {
	Redis RedisParams `mapstructure:",squash"`
}

type RedisParams struct {
	Host            string        `mapstructure:"DB_REDIS_HOST"`
	Port            int           `mapstructure:"DB_REDIS_PORT"`
	Password        string        `mapstructure:"DB_REDIS_PASSWORD"`
	DB              int           `mapstructure:"DB_REDIS_DB"`
	PoolSize        int           `mapstructure:"DB_REDIS_POOL_SIZE"`
	MinIdleConns    int           `mapstructure:"DB_REDIS_MIN_IDLE_CONNS"`
	SessionTTL      time.Duration `mapstructure:"DB_REDIS_SESSION_TTL"`
	RevokedTokenTTL time.Duration `mapstructure:"DB_REDIS_REVOKED_TOKEN_TTL"`
}

func ToRedisConfig(p RedisParams) *storage.RedisConfig {
	return &storage.RedisConfig{
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
