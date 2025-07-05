package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	redisLib "github.com/rshelekhov/golib/db/redis"
	"github.com/rshelekhov/sso/internal/config/settings"
)

type RedisConnection struct {
	Client          *redis.Client
	SessionTTL      time.Duration
	RevokedTokenTTL time.Duration
}

func NewRedisConnection(ctx context.Context, cfg settings.RedisParams) (*RedisConnection, error) {
	const method = "storage.NewRedisConnection"

	conn, err := redisLib.NewConnection(ctx,
		redisLib.WithHost(cfg.Host),
		redisLib.WithPort(cfg.Port),
		redisLib.WithPassword(cfg.Password),
		redisLib.WithDB(cfg.DB),
		redisLib.WithPoolSize(cfg.PoolSize),
		redisLib.WithMinIdleConns(cfg.MinIdleConns),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create redis connection: %w", method, err)
	}

	return &RedisConnection{
		Client:          conn.Client(),
		SessionTTL:      cfg.SessionTTL,
		RevokedTokenTTL: cfg.RevokedTokenTTL,
	}, nil
}
