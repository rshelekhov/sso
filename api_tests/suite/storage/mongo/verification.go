package mongo

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type TestVerificationStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

const verificationTokensCollectionName = "verification_tokens"

func NewTestStorage(db *mongo.Database, timeout time.Duration) (*TestVerificationStorage, error) {
	const op = "api_tests.suite.storage.verification.mongo.NewTestStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(verificationTokensCollectionName)

	return &TestVerificationStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *TestVerificationStorage) GetToken(ctx context.Context, email string, tokenType entity.VerificationTokenType) (string, error) {
	const method = "api_tests.suite.storage.verification.mongo.GetToken"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		"recipient":     email,
		"token_type_id": int32(tokenType),
	}

	result := s.coll.FindOne(ctx, filter)

	if err := result.Err(); err != nil {
		return "", fmt.Errorf("%s: failed to get verification token: %w", method, err)
	}

	var resultDoc struct {
		Token string `bson:"token"`
	}

	if err := result.Decode(&resultDoc); err != nil {
		return "", fmt.Errorf("%s: failed to decode verification token: %w", method, err)
	}

	return resultDoc.Token, nil
}

func (s *TestVerificationStorage) GetTokenExpiresAt(ctx context.Context, email string, tokenType entity.VerificationTokenType) (time.Time, error) {
	const method = "api_tests.suite.storage.verification.mongo.GetToken"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		"recipient":     email,
		"token_type_id": int32(tokenType),
	}

	result := s.coll.FindOneAndUpdate()

	return time.Time{}, nil
}

func (s *TestVerificationStorage) SetTokenExpired(ctx context.Context, email string, tokenType entity.VerificationTokenType) error {
	// TODO: implement
	return nil
}
