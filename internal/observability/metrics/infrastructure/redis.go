package infrastructure

import (
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"
)

const (
	MetricRedisOperationDuration             = "redis.operation.duration"
	MetricRedisOperationCount                = "redis.operation.count"
	MetricRedisOperationError                = "redis.operation.error"
	MetricRedisConnectionPoolAcquired        = "redis.connection.pool.acquired"
	MetricRedisConnectionPoolIdle            = "redis.connection.pool.idle"
	MetricRedisConnectionPoolAcquireDuration = "redis.connection.pool.acquire_duration"
)

type RedisMetrics struct {
	RedisOperationDuration metric.Int64Histogram // Duration of Redis operations
	RedisOperationCount    metric.Int64Counter   // Number of Redis operations performed
	RedisOperationError    metric.Int64Counter   // Number of Redis operation errors

	RedisConnectionPoolAcquired        metric.Int64UpDownCounter // Currently acquired (in-use) connections
	RedisConnectionPoolIdle            metric.Int64UpDownCounter // Currently idle (available) connections
	RedisConnectionPoolAcquireDuration metric.Int64Histogram     // Total time spent acquiring connections
}

type RedisConnectionPoolStats struct {
	Acquired        int64         // Currently acquired (in-use) connections
	Idle            int64         // Currently idle (available) connections
	AcquireDuration time.Duration // Total time spent acquiring connections
}

func NewRedisMetrics(meter metric.Meter) (*RedisMetrics, error) {
	redisOperationDuration, err := meter.Int64Histogram(
		MetricRedisOperationDuration,
		metric.WithDescription("Duration of Redis operations"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricRedisOperationDuration, err)
	}

	redisOperationCount, err := meter.Int64Counter(
		MetricRedisOperationCount,
		metric.WithDescription("Number of Redis operations performed"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRedisOperationCount, err)
	}

	redisOperationError, err := meter.Int64Counter(
		MetricRedisOperationError,
		metric.WithDescription("Number of Redis operation errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRedisOperationError, err)
	}

	redisConnectionPoolAcquired, err := meter.Int64UpDownCounter(
		MetricRedisConnectionPoolAcquired,
		metric.WithDescription("Number of active Redis connections"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRedisConnectionPoolAcquired, err)
	}

	redisConnectionPoolIdle, err := meter.Int64UpDownCounter(
		MetricRedisConnectionPoolIdle,
		metric.WithDescription("Duration of Redis connection pool wait"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRedisConnectionPoolIdle, err)
	}

	redisConnectionPoolAcquireDuration, err := meter.Int64Histogram(
		MetricRedisConnectionPoolAcquireDuration,
		metric.WithDescription("Duration of Redis connection pool acquire"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricRedisConnectionPoolAcquireDuration, err)
	}

	return &RedisMetrics{
		RedisOperationDuration:             redisOperationDuration,
		RedisOperationCount:                redisOperationCount,
		RedisOperationError:                redisOperationError,
		RedisConnectionPoolAcquired:        redisConnectionPoolAcquired,
		RedisConnectionPoolIdle:            redisConnectionPoolIdle,
		RedisConnectionPoolAcquireDuration: redisConnectionPoolAcquireDuration,
	}, nil
}
