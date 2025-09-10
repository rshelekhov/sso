package infrastructure

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
)

const (
	MetricDBOperationDuration          = "db.client.operation.duration"
	MetricDBOperationCount             = "db.client.operation.count"
	MetricDBOperationError             = "db.client.operation.error"
	MetricDBConnectionsAcquired        = "db.client.connections.acquired"
	MetricDBConnectionsIdle            = "db.client.connections.idle"
	MetricDBConnectionsTotal           = "db.client.connections.total"
	MetricDBConnectionsMax             = "db.client.connections.max"
	MetricDBConnectionsMin             = "db.client.connections.min"
	MetricDBConnectionsAcquireCount    = "db.client.connections.acquire_count"
	MetricDBConnectionsAcquireDuration = "db.client.connections.acquire_duration"
	MetricDBConnectionsConstructing    = "db.client.connections.constructing"
)

type DBClientMetrics struct {
	DBClientOperationDuration metric.Int64Histogram // Duration of database operations
	DBClientOperationCount    metric.Int64Counter   // Number of database operations performed
	DBClientOperationError    metric.Int64Counter   // Number of database operation errors

	DBClientConnectionsAcquired        metric.Int64UpDownCounter // Currently acquired (in-use) connections
	DBClientConnectionsIdle            metric.Int64UpDownCounter // Currently idle (available) connections
	DBClientConnectionsTotal           metric.Int64UpDownCounter // Total connections in pool
	DBClientConnectionsMax             metric.Int64UpDownCounter // Maximum connections allowed
	DBClientConnectionsMin             metric.Int64UpDownCounter // Minimum connections allowed
	DBClientConnectionsAcquireCount    metric.Int64Counter       // Cumulative acquire count
	DBClientConnectionsAcquireDuration metric.Int64Histogram     // Total time spent acquiring connections
	DBClientConnectionsConstructing    metric.Int64UpDownCounter // Connections being constructed
}

func NewDBClientMetrics(meter metric.Meter) (*DBClientMetrics, error) {
	dbClientOperationDuration, err := meter.Int64Histogram(
		MetricDBOperationDuration,
		metric.WithDescription("Duration of database operations"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricDBOperationDuration, err)
	}

	dbClientOperationCount, err := meter.Int64Counter(
		MetricDBOperationCount,
		metric.WithDescription("Number of database operations performed"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBOperationCount, err)
	}

	dbClientOperationError, err := meter.Int64Counter(
		MetricDBOperationError,
		metric.WithDescription("Number of database operation errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBOperationError, err)
	}

	dbClientConnectionsAcquired, err := meter.Int64UpDownCounter(
		MetricDBConnectionsAcquired,
		metric.WithDescription("Number of currently acquired database connections"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsAcquired, err)
	}

	dbClientConnectionsIdle, err := meter.Int64UpDownCounter(
		MetricDBConnectionsIdle,
		metric.WithDescription("Number of currently idle database connections"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsIdle, err)
	}

	dbClientConnectionsTotal, err := meter.Int64UpDownCounter(
		MetricDBConnectionsTotal,
		metric.WithDescription("Total number of database connections in the pool"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsTotal, err)
	}

	dbClientConnectionsMax, err := meter.Int64UpDownCounter(
		MetricDBConnectionsMax,
		metric.WithDescription("Maximum number of database connections in the pool"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsMax, err)
	}

	dbClientConnectionsMin, err := meter.Int64UpDownCounter(
		MetricDBConnectionsMin,
		metric.WithDescription("Minimum number of database connections in the pool"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsMin, err)
	}

	dbClientConnectionsAcquireCount, err := meter.Int64Counter(
		MetricDBConnectionsAcquireCount,
		metric.WithDescription("Cumulative count of successful connection acquires from the pool"),
		metric.WithUnit("{acquire}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsAcquireCount, err)
	}

	dbClientConnectionsAcquireDuration, err := meter.Int64Histogram(
		MetricDBConnectionsAcquireDuration,
		metric.WithDescription("Duration of connection acquires from the pool"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricDBConnectionsAcquireDuration, err)
	}

	dbClientConnectionsConstructing, err := meter.Int64UpDownCounter(
		MetricDBConnectionsConstructing,
		metric.WithDescription("Number of connections with construction in progress"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDBConnectionsConstructing, err)
	}

	return &DBClientMetrics{
		DBClientOperationDuration: dbClientOperationDuration,
		DBClientOperationCount:    dbClientOperationCount,
		DBClientOperationError:    dbClientOperationError,

		DBClientConnectionsAcquired:        dbClientConnectionsAcquired,
		DBClientConnectionsIdle:            dbClientConnectionsIdle,
		DBClientConnectionsTotal:           dbClientConnectionsTotal,
		DBClientConnectionsMax:             dbClientConnectionsMax,
		DBClientConnectionsMin:             dbClientConnectionsMin,
		DBClientConnectionsAcquireCount:    dbClientConnectionsAcquireCount,
		DBClientConnectionsAcquireDuration: dbClientConnectionsAcquireDuration,
		DBClientConnectionsConstructing:    dbClientConnectionsConstructing,
	}, nil
}
