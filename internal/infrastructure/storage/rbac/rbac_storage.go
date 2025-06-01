package rbac

import (
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain/service/rbac"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/rbac/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/rbac/postgres"
)

var (
	ErrMongoRBACStorageSettingsEmpty    = errors.New("mongo RBAC storage settings are empty")
	ErrPostgresRBACStorageSettingsEmpty = errors.New("postgres RBAC storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection) (rbac.Storage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown user storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (rbac.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoRBACStorageSettingsEmpty
	}

	return mongoStorage.NewRBACStorage(dbConn.Mongo.Database, dbConn.Mongo.Timeout)
}

func newPostgresStorage(dbConn *storage.DBConnection) (rbac.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresRBACStorageSettingsEmpty
	}

	return pgStorage.NewRBACStorage(dbConn.Postgres.Pool), nil
}
