package mocks

import (
	context "context"

	"github.com/rshelekhov/sso/internal/domain/usecase/client"
	"go.opentelemetry.io/otel/attribute"
)

type NoOpMetricsRecorder struct{}

var _ client.MetricsRecorder = (*NoOpMetricsRecorder)(nil)

func (m *NoOpMetricsRecorder) RecordClientRegistrationsAttempt(ctx context.Context) {}

func (m *NoOpMetricsRecorder) RecordClientRegistrationsSuccess(ctx context.Context) {}

func (m *NoOpMetricsRecorder) RecordClientRegistrationsError(ctx context.Context, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordClientDeletionsAttempt(ctx context.Context) {}

func (m *NoOpMetricsRecorder) RecordClientDeletionsSuccess(ctx context.Context) {}

func (m *NoOpMetricsRecorder) RecordClientDeletionsError(ctx context.Context, attrs ...attribute.KeyValue) {
}
