package session

import "context"

type MetricsRecorder interface {
	RecordSessionActive(ctx context.Context, clientID string)
	RecordSessionCreated(ctx context.Context, clientID string)
	RecordSessionRefreshAttempts(ctx context.Context, clientID string)
	RecordSessionDuration(ctx context.Context, clientID string, duration float64)
	RecordSessionDeletedLogout(ctx context.Context, clientID string)
	RecordSessionDeletedExpired(ctx context.Context, clientID string)
	RecordDeviceRegistrations(ctx context.Context, clientID string)
	RecordDeviceDeletions(ctx context.Context, clientID string, count int)
}
