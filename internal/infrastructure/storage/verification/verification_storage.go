package verification

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/domain/service/verification"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/verification/mongo"
	pgStorage "github.com/rshelekhov/sso/internal/infrastructure/storage/verification/postgres"
)

var (
	ErrMongoVerificationStorageSettingsEmpty    = fmt.Errorf("mongo verification storage settings are empty")
	ErrPostgresVerificationStorageSettingsEmpty = fmt.Errorf("postgres verification storage settings are empty")
)

func NewStorage(dbConn *storage.DBConnection) (verification.Storage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown verification storage type: %s", dbConn.Type)
	}
}

func newMongoStorage(dbConn *storage.DBConnection) (verification.Storage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoVerificationStorageSettingsEmpty
	}

	return mongoStorage.NewVerificationStorage(dbConn.Mongo.Client, dbConn.Mongo.DBName), nil
}

func newPostgresStorage(dbConn *storage.DBConnection) (verification.Storage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresVerificationStorageSettingsEmpty
	}

	return pgStorage.NewVerificationStorage(dbConn.Postgres.Pool), nil
}
