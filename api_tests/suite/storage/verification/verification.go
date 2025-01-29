package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/api_tests/suite/storage/verification/mongo"
	"github.com/rshelekhov/sso/api_tests/suite/storage/verification/postgres"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type TestStorage interface {
	GetToken(ctx context.Context, email string, tokenType entity.VerificationTokenType) (string, error)
	GetTokenExpiresAt(ctx context.Context, email string, tokenType entity.VerificationTokenType) (time.Time, error)
	SetTokenExpired(ctx context.Context, email string, tokenType entity.VerificationTokenType) error
}

var (
	ErrMongoVerificationStorageSettingsEmpty    = errors.New("mongo verification storage settings are empty")
	ErrPostgresVerificationStorageSettingsEmpty = errors.New("postgres verification storage settings are empty")
)

func NewTestStorage(dbConn *storage.DBConnection) (TestStorage, error) {
	switch dbConn.Type {
	case storage.TypeMongo:
		return newMongoTestStorage(dbConn)
	case storage.TypePostgres:
		return newPostgresTestStorage(dbConn)
	default:
		return nil, fmt.Errorf("unknown test verification storage type: %s", dbConn.Type)
	}
}

func newMongoTestStorage(dbConn *storage.DBConnection) (TestStorage, error) {
	if dbConn.Mongo == nil {
		return nil, ErrMongoVerificationStorageSettingsEmpty
	}

	return mongo.NewTestStorage(dbConn.Mongo.Client, dbConn.Mongo.DBName), nil
}

func newPostgresTestStorage(dbConn *storage.DBConnection) (TestStorage, error) {
	if dbConn.Postgres == nil {
		return nil, ErrPostgresVerificationStorageSettingsEmpty
	}

	return postgres.NewTestStorage(dbConn.Postgres.Pool), nil
}
