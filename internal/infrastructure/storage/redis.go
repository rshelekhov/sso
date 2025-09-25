package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	redisLib "github.com/rshelekhov/golib/db/redis"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/observability/metrics"
	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
)

type RedisConnection struct {
	Client          *redis.Client
	SessionTTL      time.Duration
	RevokedTokenTTL time.Duration
	recorder        metrics.MetricsRecorder
}

func NewRedisConnection(ctx context.Context, cfg settings.RedisParams, recorder metrics.MetricsRecorder) (*RedisConnection, error) {
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

	redisConn := &RedisConnection{
		Client:          conn.Client(),
		SessionTTL:      cfg.SessionTTL,
		RevokedTokenTTL: cfg.RevokedTokenTTL,
		recorder:        recorder,
	}

	go redisConn.collectRedisMetrics(ctx)

	return redisConn, nil
}

func (r *RedisConnection) collectRedisMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Collect metrics every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if r.Client != nil {
				poolStats := r.Client.PoolStats()

				stats := infrastructure.RedisConnectionPoolStats{
					Acquired:        int64(poolStats.TotalConns - poolStats.IdleConns),
					Idle:            int64(poolStats.IdleConns),
					AcquireDuration: time.Duration(poolStats.WaitDurationNs),
				}
				r.recorder.RecordRedisConnectionPoolStats(stats)
			}
		}
	}
}
