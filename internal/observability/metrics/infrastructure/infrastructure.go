package infrastructure

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
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

// NewNoOpMetrics creates infrastructure metrics with all NoOp implementations
func NewNoOpMetrics() *Metrics {
	// Use OpenTelemetry's NoOp meter to create proper NoOp instruments
	noopMeter := noop.NewMeterProvider().Meter("")

	// Create metrics with NoOp instruments - these will not panic when called
	grpcServer, _ := NewGRPCServerMetrics(noopMeter)
	dbClient, _ := NewDBClientMetrics(noopMeter)
	redis, _ := NewRedisMetrics(noopMeter)
	s3, _ := NewS3Metrics(noopMeter)

	return &Metrics{
		GRPCServer: grpcServer,
		DBClient:   dbClient,
		Redis:      redis,
		S3:         s3,
	}
}
