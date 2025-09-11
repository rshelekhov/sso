package business

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	MetricUserDeletionsAttempts = "user.deletions.attempts.total"
	MetricUserDeletionsSuccess  = "user.deletions.success.total"
	MetricUserDeletionsErrors   = "user.deletions.errors.total"
)

type UserMetrics struct {
	UserDeletionsAttempts metric.Int64Counter
	UserDeletionsSuccess  metric.Int64Counter
	UserDeletionsErrors   metric.Int64Counter
}

func newUserMetrics(meter metric.Meter) (*UserMetrics, error) {
	var err error
	metrics := &UserMetrics{}

	if metrics.UserDeletionsAttempts, err = createCounter(
		meter,
		MetricUserDeletionsAttempts,
		"User deletion operations by result",
		"{attempt}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserDeletionsAttempts, err)
	}

	if metrics.UserDeletionsSuccess, err = createCounter(
		meter,
		MetricUserDeletionsSuccess,
		"User deletion operations by result",
		"{success}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserDeletionsSuccess, err)
	}

	if metrics.UserDeletionsErrors, err = createCounter(
		meter,
		MetricUserDeletionsErrors,
		"User deletion operations by result",
		"{error}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserDeletionsErrors, err)
	}

	return metrics, nil
}

func (m *UserMetrics) RecordUserDeletionsAttempt(ctx context.Context, clientID string) {
	m.UserDeletionsAttempts.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *UserMetrics) RecordUserDeletionsSuccess(ctx context.Context, clientID string) {
	m.UserDeletionsSuccess.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *UserMetrics) RecordUserDeletionsError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
	attrs = append([]attribute.KeyValue{attribute.String("client.ID", clientID)}, attrs...)
	m.UserDeletionsErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}
