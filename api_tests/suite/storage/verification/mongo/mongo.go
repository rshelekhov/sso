package mongo

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type TestVerificationStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

const verificationTokensCollectionName = "verification_tokens"

func NewTestStorage(db *mongo.Database, timeout time.Duration) *TestVerificationStorage {
	coll := db.Collection(verificationTokensCollectionName)

	return &TestVerificationStorage{
		coll:    coll,
		timeout: timeout,
	}
}

func (s *TestVerificationStorage) GetToken(ctx context.Context, email string, tokenType entity.VerificationTokenType) (string, error) {
	// TODO: implement
	return "", nil
}

func (s *TestVerificationStorage) GetTokenExpiresAt(ctx context.Context, email string, tokenType entity.VerificationTokenType) (time.Time, error) {
	// TODO: implement
	return time.Time{}, nil
}

func (s *TestVerificationStorage) SetTokenExpired(ctx context.Context, email string, tokenType entity.VerificationTokenType) error {
	// TODO: implement
	return nil
}
