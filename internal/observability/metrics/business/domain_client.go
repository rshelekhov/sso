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
	clientRegistrationsAttempts, err := meter.Int64Counter(
		MetricClientRegistrationsAttempts,
		metric.WithDescription("Client registrations attempts by result"),
		metric.WithUnit("{client}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientRegistrationsAttempts, err)
	}

	clientRegistrationsSuccess, err := meter.Int64Counter(
		MetricClientRegistrationsSuccess,
		metric.WithDescription("Client registrations successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientRegistrationsSuccess, err)
	}

	clientRegistrationsErrors, err := meter.Int64Counter(
		MetricClientRegistrationsErrors,
		metric.WithDescription("Client registrations errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientRegistrationsErrors, err)
	}

	clientDeletionsAttempts, err := meter.Int64Counter(
		MetricClientDeletionsAttempts,
		metric.WithDescription("Client deletions attempts by result"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientDeletionsAttempts, err)
	}

	clientDeletionsSuccess, err := meter.Int64Counter(
		MetricClientDeletionsSuccess,
		metric.WithDescription("Client deletions successes by result"),
		metric.WithUnit("{success}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientDeletionsSuccess, err)
	}

	clientDeletionsErrors, err := meter.Int64Counter(
		MetricClientDeletionsErrors,
		metric.WithDescription("Client deletions errors by result"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricClientDeletionsErrors, err)
	}

	return &ClientMetrics{
		ClientRegistrationsAttempts: clientRegistrationsAttempts,
		ClientRegistrationsSuccess:  clientRegistrationsSuccess,
		ClientRegistrationsErrors:   clientRegistrationsErrors,
		ClientDeletionsAttempts:     clientDeletionsAttempts,
		ClientDeletionsSuccess:      clientDeletionsSuccess,
		ClientDeletionsErrors:       clientDeletionsErrors,
	}, nil
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
