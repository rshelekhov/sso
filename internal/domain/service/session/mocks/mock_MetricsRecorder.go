package mocks

import (
	context "context"

	"github.com/rshelekhov/sso/internal/domain/service/session"
)

type NoOpMetricsRecorder struct{}

var _ session.MetricsRecorder = (*NoOpMetricsRecorder)(nil)

func (m *NoOpMetricsRecorder) RecordSessionActive(ctx context.Context, clientID string) {
}
func (m *NoOpMetricsRecorder) RecordSessionCreated(ctx context.Context, clientID string) {
}
func (m *NoOpMetricsRecorder) RecordSessionRefreshAttempts(ctx context.Context, clientID string) {
}
func (m *NoOpMetricsRecorder) RecordSessionDuration(ctx context.Context, clientID string, duration float64) {
}
func (m *NoOpMetricsRecorder) RecordSessionDeletedLogout(ctx context.Context, clientID string) {
}
func (m *NoOpMetricsRecorder) RecordSessionDeletedExpired(ctx context.Context, clientID string) {
}
func (m *NoOpMetricsRecorder) RecordDeviceRegistrations(ctx context.Context, clientID string) {
}
func (m *NoOpMetricsRecorder) RecordDeviceDeletions(ctx context.Context, clientID string, count int) {
}
