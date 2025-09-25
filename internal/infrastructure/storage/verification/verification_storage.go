package verification

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/verification"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/verification/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/verification/postgres"
	"github.com/rshelekhov/sso/internal/observability/metrics"
)

var (
	ErrMongoVerificationStorageSettingsEmpty    = errors.New("mongo verification storage settings are empty")
	ErrPostgresVerificationStorageSettingsEmpty = errors.New("postgres verification storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection, txMgr transaction.Manager, recorder metrics.MetricsRecorder) (verification.Storage, error) {
	baseStorage, err := newBaseStorage(dbConn, txMgr)
	if err != nil {
		return nil, err
	}


	return newVerificationStorageDecorator(dbConn.Type.String(), baseStorage, recorder), nil
}

func newBaseStorage(dbConn *storage.DBConnection, txMgr transaction.Manager) (verification.Storage, error) {
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
		return nil, fmt.Errorf("unknown verification storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (verification.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoVerificationStorageSettingsEmpty
	}

	return mongoStorage.NewVerificationStorage(dbConn.Mongo.Database(), dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection, txMgr transaction.PostgresManager) (verification.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresVerificationStorageSettingsEmpty
	}

	return pgStorage.NewVerificationStorage(dbConn.Postgres.Pool(), txMgr), nil
}
