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
	MetricUserSearchRequests    = "user.search.requests.total"
	MetricUserSearchResults     = "user.search.results"
)

type UserMetrics struct {
	UserDeletionsAttempts metric.Int64Counter
	UserDeletionsSuccess  metric.Int64Counter
	UserDeletionsErrors   metric.Int64Counter
	UserSearchRequests    metric.Int64Counter
	UserSearchResults     metric.Int64Histogram
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

	if metrics.UserSearchRequests, err = createCounter(
		meter,
		MetricUserSearchRequests,
		"Total number of user search requests",
		"{request}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricUserSearchRequests, err)
	}

	if metrics.UserSearchResults, err = createInt64Histogram(
		meter,
		MetricUserSearchResults,
		"Number of results returned per search request",
		"{result}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricUserSearchResults, err)
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

func (m *UserMetrics) RecordUserSearchRequest(ctx context.Context, clientID string) {
	m.UserSearchRequests.Add(ctx, 1, metric.WithAttributes(attribute.String("client.ID", clientID)))
}

func (m *UserMetrics) RecordUserSearchResults(ctx context.Context, clientID string, resultCount int) {
	m.UserSearchResults.Record(ctx, int64(resultCount), metric.WithAttributes(attribute.String("client.ID", clientID)))
}
