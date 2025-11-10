package mocks

import (
	context "context"

	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"go.opentelemetry.io/otel/attribute"
)

type NoOpMetricsRecorder struct{}

var _ user.MetricsRecorder = (*NoOpMetricsRecorder)(nil)

func (m *NoOpMetricsRecorder) RecordUserDeletionsAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordUserDeletionsSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordUserDeletionsError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordUserSearchRequest(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordUserSearchResults(ctx context.Context, clientID string, resultCount int) {
}
