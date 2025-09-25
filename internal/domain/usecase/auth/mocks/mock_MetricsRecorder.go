package mocks

import (
	context "context"

	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"go.opentelemetry.io/otel/attribute"
)

type NoOpMetricsRecorder struct{}

var _ auth.MetricsRecorder = (*NoOpMetricsRecorder)(nil)

func (m *NoOpMetricsRecorder) RecordLoginAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordLoginSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordLoginError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordRegistrationAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordRegistrationSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordRegistrationError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordPasswordResetAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordPasswordResetSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordPasswordResetError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordChangePasswordAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordChangePasswordSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordChangePasswordError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordEmailVerificationAttempt(ctx context.Context) {}

func (m *NoOpMetricsRecorder) RecordEmailVerificationSuccess(ctx context.Context) {}

func (m *NoOpMetricsRecorder) RecordEmailVerificationError(ctx context.Context, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordLogoutAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordLogoutSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordLogoutError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordRefreshTokensAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordRefreshTokensSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordRefreshTokensError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordJWKSRetrievalAttempt(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordJWKSRetrievalSuccess(ctx context.Context, clientID string) {}

func (m *NoOpMetricsRecorder) RecordJWKSRetrievalError(ctx context.Context, clientID string, attrs ...attribute.KeyValue) {
}

func (m *NoOpMetricsRecorder) RecordSessionExpired(ctx context.Context, clientID string) {}
