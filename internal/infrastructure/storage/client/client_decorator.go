package client

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	"github.com/rshelekhov/sso/internal/domain/usecase/client"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

type ClientStorageDecorator struct {
	dbType                 string
	clientValidatorStorage clientvalidator.Storage
	clientStorage          client.Storage
	recorder               metrics.MetricsRecorder
}

func newClientStorageDecorator(dbType string, storage Storage, recorder metrics.MetricsRecorder) *ClientStorageDecorator {
	return &ClientStorageDecorator{
		dbType:                 dbType,
		clientValidatorStorage: storage,
		clientStorage:          storage,
		recorder:               recorder,
	}
}

func (d *ClientStorageDecorator) CheckClientIDExists(ctx context.Context, clientID string) error {
	start := time.Now()
	err := d.clientValidatorStorage.CheckClientIDExists(ctx, clientID)
	d.recorder.RecordDBOperation(d.dbType, "client.check_client_id_exists", time.Since(start), err)
	return err
}

func (d *ClientStorageDecorator) RegisterClient(ctx context.Context, data entity.ClientData) error {
	start := time.Now()
	err := d.clientStorage.RegisterClient(ctx, data)
	d.recorder.RecordDBOperation(d.dbType, "client.register", time.Since(start), err)
	return err
}

func (d *ClientStorageDecorator) DeleteClient(ctx context.Context, data entity.ClientData) error {
	start := time.Now()
	err := d.clientStorage.DeleteClient(ctx, data)
	d.recorder.RecordDBOperation(d.dbType, "client.delete", time.Since(start), err)
	return err
}
