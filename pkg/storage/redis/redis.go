package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func New(cfg *Config) (*redis.Client, error) {
	const method = "storage.redis.New"

	if cfg == nil {
		return nil, fmt.Errorf("%s: redis config is nil", method)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
	})

	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("%s: failed to ping redis: %w", method, err)
	}

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
