package app

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/app/postgres"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/user/mongo"
)

var (
	ErrMongoAppStorageSettingsEmpty    = fmt.Errorf("mongo user storage settings are empty")
	ErrPostgresAppStorageSettingsEmpty = fmt.Errorf("postgres user storage settings are empty")
)

func New(dbConn *storage.DBConnection) (userdata.Storage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown user storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (userdata.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoAppStorageSettingsEmpty
	}

	return mongoStorage.NewUserStorage(dbConn.Mongo.Client, dbConn.Mongo.DBName), nil
}

func newPostgresStorage(dbConn *storage.DBConnection) (userdata.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresAppStorageSettingsEmpty
	}

	return pgStorage.NewAppStorage(dbConn.Postgres.Pool), nil
}
