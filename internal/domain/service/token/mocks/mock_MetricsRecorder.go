package mocks

import (
	"context"

	"github.com/rshelekhov/sso/internal/domain/service/token"
)

type NoOpMetricsRecorder struct{}

var _ token.MetricsRecorder = (*NoOpMetricsRecorder)(nil)

func (m *NoOpMetricsRecorder) RecordAccessTokenIssued(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordRefreshTokenIssued(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordAccessTokenIssueFailed(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordTokenRevokedLogout(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordTokenRevokedExpired(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordTokenRevokedSecurity(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordTokenRevokedAdmin(ctx context.Context, clientID string) {
}

func (m *NoOpMetricsRecorder) RecordTokenValidationDuration(ctx context.Context, clientID string, duration float64) {
}

func (m *NoOpMetricsRecorder) RecordPrivateKeyPEMGenerationDuration(ctx context.Context, clientID string, duration float64) {
}
