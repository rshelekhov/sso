package app

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/appvalidator"
	"github.com/rshelekhov/sso/internal/domain/usecase/app"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/app/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/app/postgres"
)

var (
	ErrMongoAppStorageSettingsEmpty    = errors.New("mongo app storage settings are empty")
	ErrPostgresAppStorageSettingsEmpty = errors.New("postgres app storage settings are empty")
)

type Storage interface {
	appvalidator.Storage
	app.Storage
}

func NewStorage(dbConn *storage.DBConnection) (Storage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown app storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoAppStorageSettingsEmpty
	}

	return mongoStorage.NewAppStorage(dbConn.Mongo.Database, dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection) (Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresAppStorageSettingsEmpty
	}

	return pgStorage.NewAppStorage(dbConn.Postgres.Pool), nil
}
