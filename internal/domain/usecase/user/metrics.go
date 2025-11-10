package user

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
)

type MetricsRecorder interface {
	RecordUserDeletionsAttempt(ctx context.Context, clientID string)
	RecordUserDeletionsSuccess(ctx context.Context, clientID string)
	RecordUserDeletionsError(ctx context.Context, clientID string, attrs ...attribute.KeyValue)
	RecordUserSearchRequest(ctx context.Context, clientID string)
	RecordUserSearchResults(ctx context.Context, clientID string, resultCount int)
}
