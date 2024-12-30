package user

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/user/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/user/postgres"
)

var (
	ErrMongoUserStorageSettingsEmpty    = fmt.Errorf("mongo user storage settings are empty")
	ErrPostgresUserStorageSettingsEmpty = fmt.Errorf("postgres user storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection) (userdata.Storage, error) {
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
		return nil, ErrMongoUserStorageSettingsEmpty
	}

	return mongoStorage.NewUserStorage(dbConn.Mongo.Client, dbConn.Mongo.DBName), nil
}

func newPostgresStorage(dbConn *storage.DBConnection) (userdata.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresUserStorageSettingsEmpty
	}

	return pgStorage.NewUserStorage(dbConn.Postgres.Pool), nil
}
