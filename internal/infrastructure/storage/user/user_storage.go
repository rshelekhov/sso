package user

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/user/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/user/postgres"
)

var (
	ErrMongoUserStorageSettingsEmpty    = errors.New("mongo user storage settings are empty")
	ErrPostgresUserStorageSettingsEmpty = errors.New("postgres user storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection, txMgr transaction.Manager) (userdata.Storage, error) {
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
		return nil, fmt.Errorf("unknown user storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (userdata.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoUserStorageSettingsEmpty
	}

	return mongoStorage.NewUserStorage(dbConn.Mongo.Connection.Database(), dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection, txMgr transaction.PostgresManager) (userdata.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresUserStorageSettingsEmpty
	}

	return pgStorage.NewUserStorage(dbConn.Postgres.Connection.Pool(), txMgr), nil
}
