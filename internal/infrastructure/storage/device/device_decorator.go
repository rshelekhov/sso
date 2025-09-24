package device

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

type DeviceStorageDecorator struct {
	dbType   string
	storage  session.DeviceStorage
	recorder metrics.MetricsRecorder
}

func newDeviceStorageDecorator(dbType string, storage session.DeviceStorage, recorder metrics.MetricsRecorder) *DeviceStorageDecorator {
	return &DeviceStorageDecorator{
		dbType:   dbType,
		storage:  storage,
		recorder: recorder,
	}
}

func (d *DeviceStorageDecorator) RegisterDevice(ctx context.Context, device entity.UserDevice) error {
	start := time.Now()
	err := d.storage.RegisterDevice(ctx, device)
	d.recorder.RecordDBOperation(d.dbType, "device.register", time.Since(start), err)
	return err
}

func (d *DeviceStorageDecorator) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	start := time.Now()
	deviceID, err := d.storage.GetUserDeviceID(ctx, userID, userAgent)
	d.recorder.RecordDBOperation(d.dbType, "device.get_user_device_id", time.Since(start), err)
	return deviceID, err
}

func (d *DeviceStorageDecorator) UpdateLastVisitedAt(ctx context.Context, session entity.Session) error {
	start := time.Now()
	err := d.storage.UpdateLastVisitedAt(ctx, session)
	d.recorder.RecordDBOperation(d.dbType, "device.update_last_visited_at", time.Since(start), err)
	return err
}

func (d *DeviceStorageDecorator) DeleteAllUserDevices(ctx context.Context, userID string) (int, error) {
	start := time.Now()
	deletedDevicesCount, err := d.storage.DeleteAllUserDevices(ctx, userID)
	d.recorder.RecordDBOperation(d.dbType, "device.delete_all_user_devices", time.Since(start), err)
	return deletedDevicesCount, err
}
