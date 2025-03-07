package storage

import (
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	redisStorage "github.com/rshelekhov/sso/pkg/storage/redis"
)

type RedisConnection struct {
	Client          *redis.Client
	SessionTTL      time.Duration
	RevokedTokenTTL time.Duration
}

func NewRedisConnection(cfg RedisConfig) (*RedisConnection, error) {
	const method = "storage.NewRedisConnection"

	client, err := redisStorage.New(cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create redis client: %w", method, err)
	}

	return &RedisConnection{
		Client:          client,
		SessionTTL:      cfg.SessionTTL,
		RevokedTokenTTL: cfg.RevokedTokenTTL,
	}, nil
}

type RedisConfig struct {
	Redis           *redisStorage.Config
	SessionTTL      time.Duration
	RevokedTokenTTL time.Duration
}
