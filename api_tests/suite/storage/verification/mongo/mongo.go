package mongo

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type TestStorage struct {
	client *mongo.Client
	dbName string
}

func NewTestStorage(client *mongo.Client, dbName string) *TestStorage {
	return &TestStorage{
		client: client,
		dbName: dbName,
	}
}

func (s *TestStorage) GetToken(ctx context.Context, email string, tokenType entity.VerificationTokenType) (string, error) {
	// TODO: implement
	return "", nil
}

func (s *TestStorage) GetTokenExpiresAt(ctx context.Context, email string, tokenType entity.VerificationTokenType) (time.Time, error) {
	// TODO: implement
	return time.Time{}, nil
}

func (s *TestStorage) SetTokenExpired(ctx context.Context, email string, tokenType entity.VerificationTokenType) error {
	// TODO: implement
	return nil
}
