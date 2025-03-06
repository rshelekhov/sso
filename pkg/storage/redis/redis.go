package redis

import (
	"fmt"

	"github.com/redis/go-redis/v9"
)

func New(cfg *Config) (*redis.Client, error) {
	const method = "storage.redis.New"

	if cfg == nil {
		return nil, fmt.Errorf("%s:redis config is nil", method)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
	})

	return client, nil
}

type Config struct {
	Host         string
	Port         int
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
}
