package business

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	MetricClientRegistrationsAttempts = "client.registrations.attempts.total"
	MetricClientRegistrationsSuccess  = "client.registrations.success.total"
	MetricClientRegistrationsErrors   = "client.registrations.errors.total"

	MetricClientDeletionsAttempts = "client.deletions.attempts.total"
	MetricClientDeletionsSuccess  = "client.deletions.success.total"
	MetricClientDeletionsErrors   = "client.deletions.errors.total"
)

type ClientMetrics struct {
	ClientRegistrationsAttempts metric.Int64Counter
	ClientRegistrationsSuccess  metric.Int64Counter
	ClientRegistrationsErrors   metric.Int64Counter

	ClientDeletionsAttempts metric.Int64Counter
	ClientDeletionsSuccess  metric.Int64Counter
	ClientDeletionsErrors   metric.Int64Counter
}

func newClientMetrics(meter metric.Meter) (*ClientMetrics, error) {
	var err error
	metrics := &ClientMetrics{}

	if metrics.ClientRegistrationsAttempts, err = createCounter(
		meter,
		MetricClientRegistrationsAttempts,
		"Client registrations attempts by result",
		"{client}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientRegistrationsAttempts, err)
	}

	if metrics.ClientRegistrationsSuccess, err = createCounter(
		meter,
		MetricClientRegistrationsSuccess,
		"Client registrations successes by result",
		"{success}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientRegistrationsSuccess, err)
	}

	if metrics.ClientRegistrationsErrors, err = createCounter(
		meter,
		MetricClientRegistrationsErrors,
		"Client registrations errors by result",
		"{error}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientRegistrationsErrors, err)
	}

	if metrics.ClientDeletionsAttempts, err = createCounter(
		meter,
		MetricClientDeletionsAttempts,
		"Client deletions attempts by result",
		"{client}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientDeletionsAttempts, err)
	}

	if metrics.ClientDeletionsSuccess, err = createCounter(
		meter,
		MetricClientDeletionsSuccess,
		"Client deletions successes by result",
		"{success}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientDeletionsSuccess, err)
	}

	if metrics.ClientDeletionsErrors, err = createCounter(
		meter,
		MetricClientDeletionsErrors,
		"Client deletions errors by result",
		"{error}",
	); err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientDeletionsErrors, err)
	}

	return metrics, nil
}

func (m *ClientMetrics) RecordClientRegistrationsAttempt(ctx context.Context) {
	m.ClientRegistrationsAttempts.Add(ctx, 1)
}

func (m *ClientMetrics) RecordClientRegistrationsSuccess(ctx context.Context) {
	m.ClientRegistrationsSuccess.Add(ctx, 1)
}

func (m *ClientMetrics) RecordClientRegistrationsError(ctx context.Context, attrs ...attribute.KeyValue) {
	m.ClientRegistrationsErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (m *ClientMetrics) RecordClientDeletionsAttempt(ctx context.Context) {
	m.ClientDeletionsAttempts.Add(ctx, 1)
}

func (m *ClientMetrics) RecordClientDeletionsSuccess(ctx context.Context) {
	m.ClientDeletionsSuccess.Add(ctx, 1)
}

func (m *ClientMetrics) RecordClientDeletionsError(ctx context.Context, attrs ...attribute.KeyValue) {
	m.ClientDeletionsErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}
