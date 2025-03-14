package device

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/device/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/device/postgres"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
)

var (
	ErrMongoDeviceStorageSettingsEmpty    = errors.New("mongo device storage settings are empty")
	ErrPostgresDeviceStorageSettingsEmpty = errors.New("postgres device storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection, txMgr transaction.Manager) (session.DeviceStorage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		pgTxMgr, ok := txMgr.(transaction.PostgresManager)
		if !ok {
			return nil, fmt.Errorf("invalid transaction manager for Postgres")
		}
		return newPostgresStorage(dbConn, pgTxMgr)
	default:
		return nil, fmt.Errorf("unknown session storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (session.DeviceStorage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoDeviceStorageSettingsEmpty
	}

	return mongoStorage.NewDeviceStorage(dbConn.Mongo.Database, dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection, txMgr transaction.PostgresManager) (session.DeviceStorage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresDeviceStorageSettingsEmpty
	}

	return pgStorage.NewDeviceStorage(dbConn.Postgres.Pool, txMgr), nil
}
