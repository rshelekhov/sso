package business

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	MetricSessionActive          = "session.active.total"
	MetricSessionCreated         = "session.created.total"
	MetricSessionRefreshAttempts = "session.refresh.attempts.total"
	MetricSessionDuration        = "session.duration.seconds"
	MetricSessionDeleted         = "session.deleted.total"
	MetricDeviceRegistrations    = "device.registrations.total"
	MetricDeviceDeletions        = "device.deletions.total"
)

type SessionMetrics struct {
	SessionActive          metric.Int64UpDownCounter
	SessionCreated         metric.Int64Counter
	SessionRefreshAttempts metric.Int64Counter
	SessionDuration        metric.Float64Histogram
	SessionDeleted         metric.Int64Counter

	// Device management metrics
	DeviceRegistrations metric.Int64Counter
	DeviceDeletions     metric.Int64Counter
}

func newSessionMetrics(meter metric.Meter) (*SessionMetrics, error) {
	var err error
	metrics := &SessionMetrics{}

	if metrics.SessionActive, err = createUpDownCounter(
		meter,
		MetricSessionActive,
		"Active sessions by client",
		"{session}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricSessionActive, err)
	}

	if metrics.SessionCreated, err = createCounter(
		meter,
		MetricSessionCreated,
		"Sessions created by result",
		"{session}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricSessionCreated, err)
	}

	if metrics.SessionRefreshAttempts, err = createCounter(
		meter,
		MetricSessionRefreshAttempts,
		"Token refresh attempts by result",
		"{attempt}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricSessionRefreshAttempts, err)
	}

	if metrics.SessionDuration, err = createHistogram(
		meter,
		MetricSessionDuration,
		"Session lifetime distribution",
		"s",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricSessionDuration, err)
	}

	if metrics.SessionDeleted, err = createCounter(
		meter,
		MetricSessionDeleted,
		"Sessions deleted by result",
		"{session}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricSessionDeleted, err)
	}

	if metrics.DeviceRegistrations, err = createCounter(
		meter,
		MetricDeviceRegistrations,
		"New device registrations",
		"{device}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDeviceRegistrations, err)
	}

	if metrics.DeviceDeletions, err = createCounter(
		meter,
		MetricDeviceDeletions,
		"Device cleanup operations",
		"{device}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricDeviceDeletions, err)
	}

	return metrics, nil
}

func (m *SessionMetrics) RecordSessionActive(ctx context.Context, clientID string) {
	m.SessionActive.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *SessionMetrics) RecordSessionCreated(ctx context.Context, clientID string) {
	m.SessionCreated.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *SessionMetrics) RecordSessionRefreshAttempts(ctx context.Context, clientID string) {
	m.SessionRefreshAttempts.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *SessionMetrics) RecordSessionDuration(ctx context.Context, clientID string, duration float64) {
	m.SessionDuration.Record(ctx, duration,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *SessionMetrics) RecordSessionDeletedLogout(ctx context.Context, clientID string) {
	m.recordSessionInactive(ctx, clientID)

	m.SessionDeleted.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
		metric.WithAttributes(attribute.String("reason", "logout")),
	)
}

func (m *SessionMetrics) RecordSessionDeletedExpired(ctx context.Context, clientID string) {
	m.recordSessionInactive(ctx, clientID)

	m.SessionDeleted.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
		metric.WithAttributes(attribute.String("reason", "expired")),
	)
}

func (m *SessionMetrics) RecordSessionDeletedSecurity(ctx context.Context, clientID string) {
	m.recordSessionInactive(ctx, clientID)

	m.SessionDeleted.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
		metric.WithAttributes(attribute.String("reason", "security")),
	)
}

func (m *SessionMetrics) RecordDeviceRegistrations(ctx context.Context, clientID string) {
	m.DeviceRegistrations.Add(ctx, 1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *SessionMetrics) RecordDeviceDeletions(ctx context.Context, clientID string, count int) {
	m.DeviceDeletions.Add(ctx, int64(count),
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}

func (m *SessionMetrics) recordSessionInactive(ctx context.Context, clientID string) {
	m.SessionActive.Add(ctx, -1,
		metric.WithAttributes(attribute.String("client.ID", clientID)),
	)
}
