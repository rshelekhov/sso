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

	userDeletionsAttempts, err := meter.Int64Counter(
		MetricUserDeletionsAttempts,
		metric.WithDescription("User deletion operations by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserDeletionsAttempts, err)
	}

	userDeletionsSuccess, err := meter.Int64Counter(
		MetricUserDeletionsSuccess,
		metric.WithDescription("User deletion operations by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserDeletionsSuccess, err)
	}

	userDeletionsErrors, err := meter.Int64Counter(
		MetricUserDeletionsErrors,
		metric.WithDescription("User deletion operations by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserDeletionsErrors, err)
	}

	return &UserMetrics{
		UserDeletionsAttempts: userDeletionsAttempts,
		UserDeletionsSuccess:  userDeletionsSuccess,
		UserDeletionsErrors:   userDeletionsErrors,
	}, nil
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
