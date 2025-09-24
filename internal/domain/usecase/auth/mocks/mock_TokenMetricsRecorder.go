package mocks

import (
	context "context"

	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
)

type NoOpTokenMetricsRecorder struct{}

var _ auth.TokenMetricsRecorder = (*NoOpTokenMetricsRecorder)(nil)

func (m *NoOpTokenMetricsRecorder) RecordTokenRevokedLogout(ctx context.Context, clientID string) {
}
