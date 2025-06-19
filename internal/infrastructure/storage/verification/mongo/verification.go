package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/mongo"
)

type VerificationStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

const verificationTokensCollectionName = "verification_tokens"

func NewVerificationStorage(db *mongo.Database, timeout time.Duration) (*VerificationStorage, error) {
	const op = "storage.verification.mongo.NewVerificationStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(verificationTokensCollectionName)

	return &VerificationStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *VerificationStorage) SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error {
	const method = "storage.verification.mongo.SaveVerificationToken"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := toTokenDoc(data)

	if _, err := s.coll.InsertOne(ctx, doc); err != nil {
		return fmt.Errorf("%s: failed to save verification token: %w", method, err)
	}
	return nil
}

func (s *VerificationStorage) GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	const method = "storage.verification.mongo.GetVerificationTokenData"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{fieldToken: token}

	result := s.coll.FindOne(ctx, filter)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return entity.VerificationToken{}, storage.ErrVerificationTokenNotFound
		}
		return entity.VerificationToken{}, fmt.Errorf("%s: failed to get verification token data: %w", method, err)
	}

	var tokenDoc tokenDocument
	if err := result.Decode(&tokenDoc); err != nil {
		return entity.VerificationToken{}, fmt.Errorf("%s: failed to decode token data: %w", method, err)
	}

	return toVerificationTokenEntity(tokenDoc), nil
}

func (s *VerificationStorage) DeleteVerificationToken(ctx context.Context, token string) error {
	const method = "storage.verification.mongo.DeleteVerificationToken"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{fieldToken: token}

	result, err := s.coll.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: failed to delete verification token: %w", method, err)
	}

	if result.DeletedCount == 0 {
		return storage.ErrVerificationTokenNotFound
	}

	return nil
}

func (s *VerificationStorage) DeleteAllTokens(ctx context.Context, clientID, userID string) error {
	const method = "storage.verification.mongo.DeleteAllTokens"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldAppID:  clientID,
		fieldUserID: userID,
	}

	if _, err := s.coll.DeleteMany(ctx, filter); err != nil {
		return fmt.Errorf("%s: failed to delete all tokens: %w", method, err)
	}
	return nil
}
