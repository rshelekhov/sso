package metrics

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type Recorder struct {
	dbMetrics    *infrastructure.DBClientMetrics
	s3Metrics    *infrastructure.S3Metrics
	redisMetrics *infrastructure.RedisMetrics
}

func NewRecorder(registry *Registry) *Recorder {
	if registry == nil {
		return &Recorder{}
	}

	return &Recorder{
		dbMetrics:    registry.Infrastructure.DBClient,
		s3Metrics:    registry.Infrastructure.S3,
		redisMetrics: registry.Infrastructure.Redis,
	}
}

func (r *Recorder) RecordDBOperation(dbType, operation string, duration time.Duration, err error) {
	if r == nil || r.dbMetrics == nil {
		return
	}

	ctx := context.Background()
	dbTypeAttr := attribute.String("db_type", dbType)
	operationAttr := attribute.String("operation", operation)

	r.dbMetrics.DBClientOperationDuration.Record(
		ctx,
		duration.Milliseconds(),
		metric.WithAttributes(
			dbTypeAttr,
			operationAttr,
		),
	)

	r.dbMetrics.DBClientOperationCount.Add(
		ctx,
		1,
		metric.WithAttributes(
			dbTypeAttr,
			operationAttr,
		),
	)

	if err != nil {
		r.dbMetrics.DBClientOperationError.Add(
			ctx,
			1,
			metric.WithAttributes(
				dbTypeAttr,
				operationAttr,
				attribute.String("error_type", extractDBErrorType(err)),
			),
		)
	}
}

func (r *Recorder) RecordS3Operation(operation string, duration time.Duration, err error) {
	if r == nil || r.s3Metrics == nil {
		return
	}

	ctx := context.Background()
	operationAttr := attribute.String("operation", operation)

	r.s3Metrics.S3OperationDuration.Record(
		ctx,
		duration.Milliseconds(),
		metric.WithAttributes(operationAttr),
	)

	r.s3Metrics.S3OperationCount.Add(
		ctx,
		1,
		metric.WithAttributes(operationAttr),
	)

	r.s3Metrics.S3HTTPRequestDuration.Record(
		ctx,
		duration.Milliseconds(),
		metric.WithAttributes(operationAttr),
	)

	if err != nil {
		errorAttrs := []attribute.KeyValue{
			operationAttr,
			attribute.String("error_code", extractS3ErrorCode(err)),
		}
		r.s3Metrics.S3OperationError.Add(
			ctx,
			1,
			metric.WithAttributes(errorAttrs...),
		)
	}
}

func (r *Recorder) RecordRedisOperation(operation string, duration time.Duration, err error) {
	if r == nil || r.redisMetrics == nil {
		return
	}

	ctx := context.Background()
	operationAttr := attribute.String("operation", operation)

	r.redisMetrics.RedisOperationDuration.Record(
		ctx,
		duration.Milliseconds(),
		metric.WithAttributes(operationAttr),
	)

	r.redisMetrics.RedisOperationCount.Add(
		ctx,
		1,
		metric.WithAttributes(operationAttr),
	)

	if err != nil {
		errorAttrs := []attribute.KeyValue{
			operationAttr,
			attribute.String("error_type", extractRedisErrorType(err)),
		}
		r.redisMetrics.RedisOperationError.Add(
			ctx,
			1,
			metric.WithAttributes(errorAttrs...),
		)
	}
}

func (r *Recorder) RecordDBConnectionPoolStats(dbType string, stats infrastructure.PostgresConnectionPoolStats) {
	if r == nil || r.dbMetrics == nil {
		return
	}

	ctx := context.Background()
	dbTypeAttr := attribute.String("db_type", dbType)

	r.dbMetrics.DBClientConnectionsAcquired.Add(
		ctx,
		stats.Acquired,
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsIdle.Add(
		ctx,
		stats.Idle,
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsTotal.Add(
		ctx,
		stats.Total,
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsMax.Add(
		ctx,
		stats.Max,
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsMin.Add(
		ctx,
		stats.Min,
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsAcquireCount.Add(
		ctx,
		stats.AcquireCount,
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsAcquireDuration.Record(
		ctx,
		stats.AcquireDuration.Milliseconds(),
		metric.WithAttributes(dbTypeAttr),
	)

	r.dbMetrics.DBClientConnectionsConstructing.Add(
		ctx,
		stats.Constructing,
		metric.WithAttributes(dbTypeAttr),
	)
}

func (r *Recorder) RecordRedisConnectionPoolStats(stats infrastructure.RedisConnectionPoolStats) {
	if r == nil || r.redisMetrics == nil {
		return
	}

	ctx := context.Background()

	r.redisMetrics.RedisConnectionPoolAcquired.Add(
		ctx,
		stats.Acquired,
	)

	r.redisMetrics.RedisConnectionPoolIdle.Add(
		ctx,
		stats.Idle,
	)

	r.redisMetrics.RedisConnectionPoolAcquireDuration.Record(
		ctx,
		stats.AcquireDuration.Milliseconds(),
	)
}
