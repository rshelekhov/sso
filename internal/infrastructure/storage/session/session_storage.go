package session

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/session/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/session/postgres"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
)

var (
	ErrMongoSessionStorageSettingsEmpty    = errors.New("mongo session storage settings are empty")
	ErrPostgresSessionStorageSettingsEmpty = errors.New("postgres session storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection, txMgr transaction.Manager) (session.Storage, error) {
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

func newMongoStorage(dbConn *storage.DBConnection) (session.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoSessionStorageSettingsEmpty
	}

	return mongoStorage.NewSessionStorage(dbConn.Mongo.Database, dbConn.Mongo.Timeout), nil
}

func newPostgresStorage(dbConn *storage.DBConnection, txMgr transaction.PostgresManager) (session.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresSessionStorageSettingsEmpty
	}

	return pgStorage.NewSessionStorage(dbConn.Postgres.Pool, txMgr), nil
}
