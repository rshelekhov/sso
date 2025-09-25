package verification

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/verification"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

type VerificationStorageDecorator struct {
	dbType   string
	storage  verification.Storage
	recorder metrics.MetricsRecorder
}

func newVerificationStorageDecorator(dbType string, storage verification.Storage, recorder metrics.MetricsRecorder) *VerificationStorageDecorator {
	return &VerificationStorageDecorator{
		dbType:   dbType,
		storage:  storage,
		recorder: recorder,
	}
}

func (d *VerificationStorageDecorator) SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error {
	start := time.Now()
	err := d.storage.SaveVerificationToken(ctx, data)
	d.recorder.RecordDBOperation(d.dbType, "verification.save_verification_token", time.Since(start), err)
	return err
}

func (d *VerificationStorageDecorator) GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	start := time.Now()
	data, err := d.storage.GetVerificationTokenData(ctx, token)
	d.recorder.RecordDBOperation(d.dbType, "verification.get_verification_token_data", time.Since(start), err)
	return data, err
}

func (d *VerificationStorageDecorator) DeleteVerificationToken(ctx context.Context, token string) error {
	start := time.Now()
	err := d.storage.DeleteVerificationToken(ctx, token)
	d.recorder.RecordDBOperation(d.dbType, "verification.delete_verification_token", time.Since(start), err)
	return err
}

func (d *VerificationStorageDecorator) DeleteAllTokens(ctx context.Context, userID string) error {
	start := time.Now()
	err := d.storage.DeleteAllTokens(ctx, userID)
	d.recorder.RecordDBOperation(d.dbType, "verification.delete_all_tokens", time.Since(start), err)
	return err
}
