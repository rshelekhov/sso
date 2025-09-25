package metrics

import (
	"time"

	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
)

type MetricsRecorder interface {
	RecordDBOperation(dbType, operation string, duration time.Duration, err error)
	RecordS3Operation(operation string, duration time.Duration, err error)
	RecordRedisOperation(operation string, duration time.Duration, err error)
	RecordDBConnectionPoolStats(dbType string, stats infrastructure.PostgresConnectionPoolStats)
	RecordRedisConnectionPoolStats(stats infrastructure.RedisConnectionPoolStats)
}

type NoOpRecorder struct{}

func (n *NoOpRecorder) RecordDBOperation(dbType, operation string, duration time.Duration, err error) {
	// Do nothing
}

func (n *NoOpRecorder) RecordS3Operation(operation string, duration time.Duration, err error) {
	// Do nothing
}

func (n *NoOpRecorder) RecordRedisOperation(operation string, duration time.Duration, err error) {
	// Do nothing
}

func (n *NoOpRecorder) RecordDBConnectionPoolStats(dbType string, stats infrastructure.PostgresConnectionPoolStats) {
	// Do nothing
}

func (n *NoOpRecorder) RecordRedisConnectionPoolStats(stats infrastructure.RedisConnectionPoolStats) {
	// Do nothing
}
