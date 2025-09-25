package user

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

type UserStorageDecorator struct {
	dbType   string
	storage  userdata.Storage
	recorder metrics.MetricsRecorder
}

func newUserStorageDecorator(dbType string, storage userdata.Storage, recorder metrics.MetricsRecorder) *UserStorageDecorator {
	return &UserStorageDecorator{
		dbType:   dbType,
		storage:  storage,
		recorder: recorder,
	}
}

func (d *UserStorageDecorator) GetUserByID(ctx context.Context, userID string) (entity.User, error) {
	start := time.Now()
	user, err := d.storage.GetUserByID(ctx, userID)
	d.recorder.RecordDBOperation(d.dbType, "user.get_by_id", time.Since(start), err)
	return user, err
}

func (d *UserStorageDecorator) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	start := time.Now()
	user, err := d.storage.GetUserByEmail(ctx, email)
	d.recorder.RecordDBOperation(d.dbType, "user.get_by_email", time.Since(start), err)
	return user, err
}

func (d *UserStorageDecorator) GetUserData(ctx context.Context, userID string) (entity.User, error) {
	start := time.Now()
	user, err := d.storage.GetUserData(ctx, userID)
	d.recorder.RecordDBOperation(d.dbType, "user.get_data", time.Since(start), err)
	return user, err
}

func (d *UserStorageDecorator) UpdateUser(ctx context.Context, user entity.User) error {
	start := time.Now()
	err := d.storage.UpdateUser(ctx, user)
	d.recorder.RecordDBOperation(d.dbType, "user.update", time.Since(start), err)
	return err
}

func (d *UserStorageDecorator) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	start := time.Now()
	status, err := d.storage.GetUserStatusByEmail(ctx, email)
	d.recorder.RecordDBOperation(d.dbType, "user.get_status_by_email", time.Since(start), err)
	return status, err
}

func (d *UserStorageDecorator) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	start := time.Now()
	status, err := d.storage.GetUserStatusByID(ctx, userID)
	d.recorder.RecordDBOperation(d.dbType, "user.get_status_by_id", time.Since(start), err)
	return status, err
}

func (d *UserStorageDecorator) DeleteUser(ctx context.Context, user entity.User) error {
	start := time.Now()
	err := d.storage.DeleteUser(ctx, user)
	d.recorder.RecordDBOperation(d.dbType, "user.delete", time.Since(start), err)
	return err
}
