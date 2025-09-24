package client

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
)

type MetricsRecorder interface {
	RecordClientRegistrationsAttempt(ctx context.Context)
	RecordClientRegistrationsSuccess(ctx context.Context)
	RecordClientRegistrationsError(ctx context.Context, attrs ...attribute.KeyValue)
	RecordClientDeletionsAttempt(ctx context.Context)
	RecordClientDeletionsSuccess(ctx context.Context)
	RecordClientDeletionsError(ctx context.Context, attrs ...attribute.KeyValue)
}
