package session

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/domain/service/session"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/session/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/session/postgres"
)

var (
	ErrMongoSessionStorageSettingsEmpty    = fmt.Errorf("mongo session storage settings are empty")
	ErrPostgresSessionStorageSettingsEmpty = fmt.Errorf("postgres session storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection) (session.Storage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown session storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (session.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoSessionStorageSettingsEmpty
	}

	return mongoStorage.NewSessionStorage(dbConn.Mongo.Client, dbConn.Mongo.DBName), nil
}

func newPostgresStorage(dbConn *storage.DBConnection) (session.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresSessionStorageSettingsEmpty
	}

	return pgStorage.NewSessionStorage(dbConn.Postgres.Pool), nil
}
