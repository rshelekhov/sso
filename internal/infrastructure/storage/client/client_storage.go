package client

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	"github.com/rshelekhov/sso/internal/domain/usecase/client"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/client/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/client/postgres"
)

var (
	ErrMongoClientStorageSettingsEmpty    = errors.New("mongo client storage settings are empty")
	ErrPostgresClientStorageSettingsEmpty = errors.New("postgres client storage settings are empty")
)

type Storage interface {
	clientvalidator.Storage
	client.Storage
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
		return nil, ErrMongoClientStorageSettingsEmpty
	}

	return mongoStorage.NewClientStorage(dbConn.Mongo.Connection.Database(), dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection) (Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresClientStorageSettingsEmpty
	}

	return pgStorage.NewClientStorage(dbConn.Postgres.Connection.Pool()), nil
}
