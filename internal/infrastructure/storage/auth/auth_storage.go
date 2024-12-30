package auth

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/domain/usecase/auth"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/auth/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/auth/postgres"
)

var (
	ErrMongoAuthStorageSettingsEmpty    = fmt.Errorf("mongo auth storage settings are empty")
	ErrPostgresAuthStorageSettingsEmpty = fmt.Errorf("postgres auth storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection) (auth.Storage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown auth storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (auth.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoAuthStorageSettingsEmpty
	}

	return mongoStorage.NewAuthStorage(dbConn.Mongo.Client, dbConn.Mongo.DBName), nil
}

func newPostgresStorage(dbConn *storage.DBConnection) (auth.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresAuthStorageSettingsEmpty
	}

	return pgStorage.NewAuthStorage(dbConn.Postgres.Pool), nil
}
