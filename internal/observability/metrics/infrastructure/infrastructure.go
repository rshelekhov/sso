package infrastructure

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
)

type Metrics struct {
	GRPCServer *GRPCServerMetrics
	DBClient   *DBClientMetrics
	Redis      *RedisMetrics
	S3         *S3Metrics
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	const op = "infrastructure.NewMetrics"

	grpcServer, err := NewGRPCServerMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create gRPC server metrics: %w", op, err)
	}

	dbClient, err := NewDBClientMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create db client metrics: %w", op, err)
	}

	redis, err := NewRedisMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create redis metrics: %w", op, err)
	}

	s3, err := NewS3Metrics(meter)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create s3 metrics: %w", op, err)
	}

	return &Metrics{
		GRPCServer: grpcServer,
		DBClient:   dbClient,
		Redis:      redis,
		S3:         s3,
	}, nil
}
