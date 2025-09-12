package auth

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/auth/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/auth/postgres"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

var (
	ErrMongoAuthStorageSettingsEmpty    = errors.New("mongo auth storage settings are empty")
	ErrPostgresAuthStorageSettingsEmpty = errors.New("postgres auth storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection, txMgr transaction.Manager, recorder metrics.MetricsRecorder) (auth.Storage, error) {
	baseStorage, err := newBaseStorage(dbConn, txMgr)
	if err != nil {
		return nil, err
	}

	if recorder == nil {
		recorder = &metrics.NoOpRecorder{}
	}

	return newAuthStorageDecorator(dbConn.Type.String(), baseStorage, recorder), nil
}

func newBaseStorage(dbConn *storage.DBConnection, txMgr transaction.Manager) (auth.Storage, error) {
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
		return nil, fmt.Errorf("unknown auth storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (auth.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoAuthStorageSettingsEmpty
	}

	return mongoStorage.NewAuthStorage(dbConn.Mongo.Database(), dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection, txMgr transaction.PostgresManager) (auth.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresAuthStorageSettingsEmpty
	}

	return pgStorage.NewAuthStorage(dbConn.Postgres.Pool(), txMgr), nil
}
