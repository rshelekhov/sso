package auth

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

type AuthStorageDecorator struct {
	dbType   string
	storage  auth.Storage
	recorder metrics.MetricsRecorder
}

func newAuthStorageDecorator(dbType string, storage auth.Storage, recorder metrics.MetricsRecorder) *AuthStorageDecorator {
	return &AuthStorageDecorator{
		dbType:   dbType,
		storage:  storage,
		recorder: recorder,
	}
}

func (d *AuthStorageDecorator) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	start := time.Now()
	err := d.storage.ReplaceSoftDeletedUser(ctx, user)
	d.recorder.RecordDBOperation(d.dbType, "auth.replace_soft_deleted_user", time.Since(start), err)
	return err
}

func (d *AuthStorageDecorator) RegisterUser(ctx context.Context, user entity.User) error {
	start := time.Now()
	err := d.storage.RegisterUser(ctx, user)
	d.recorder.RecordDBOperation(d.dbType, "auth.register_user", time.Since(start), err)
	return err
}

func (d *AuthStorageDecorator) MarkEmailVerified(ctx context.Context, userID string) error {
	start := time.Now()
	err := d.storage.MarkEmailVerified(ctx, userID)
	d.recorder.RecordDBOperation(d.dbType, "auth.mark_email_verified", time.Since(start), err)
	return err
}
