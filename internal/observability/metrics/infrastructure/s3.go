package infrastructure

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
)

const (
	MetricS3OperationDuration   = "s3.operation.duration"
	MetricS3OperationCount      = "s3.operation.count"
	MetricS3OperationError      = "s3.operation.error"
	MetricS3HTTPRequestDuration = "s3.http.request.duration"
)

type S3Metrics struct {
	S3OperationDuration   metric.Int64Histogram
	S3OperationCount      metric.Int64Counter
	S3OperationError      metric.Int64Counter
	S3HTTPRequestDuration metric.Int64Histogram
}

func NewS3Metrics(meter metric.Meter) (*S3Metrics, error) {
	s3OperationDuration, err := meter.Int64Histogram(
		MetricS3OperationDuration,
		metric.WithDescription("Duration of S3 operations"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricS3OperationDuration, err)
	}

	s3OperationCount, err := meter.Int64Counter(
		MetricS3OperationCount,
		metric.WithDescription("Number of S3 operations performed"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricS3OperationCount, err)
	}

	s3OperationError, err := meter.Int64Counter(
		MetricS3OperationError,
		metric.WithDescription("Number of S3 operation errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricS3OperationError, err)
	}

	s3HTTPRequestDuration, err := meter.Int64Histogram(
		MetricS3HTTPRequestDuration,
		metric.WithDescription("Duration of S3 HTTP requests"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricS3HTTPRequestDuration, err)
	}

	return &S3Metrics{
		S3OperationDuration:   s3OperationDuration,
		S3OperationCount:      s3OperationCount,
		S3OperationError:      s3OperationError,
		S3HTTPRequestDuration: s3HTTPRequestDuration,
	}, nil
}
