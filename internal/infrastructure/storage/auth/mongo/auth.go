package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/mongo/common"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuthStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewAuthStorage(db *mongo.Database, timeout time.Duration) (*AuthStorage, error) {
	const op = "storage.auth.mongo.NewAuthStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(common.UsersCollectionName)

	return &AuthStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	const method = "storage.auth.mongo.ReplaceSoftDeletedUser"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldEmail:    user.Email,
		common.FieldClientID: user.ClientID,
		common.FieldDeletedAt: bson.M{
			"$ne": nil,
		},
	}

	result, err := s.coll.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: failed to delete soft deleted user: %w", method, err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("%s: no soft deleted user found with email %s", method, user.Email)
	}

	doc := common.ToUserDoc(user)

	_, err = s.coll.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("%s: failed to register new user: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) RegisterUser(ctx context.Context, user entity.User) error {
	const method = "storage.auth.mongo.RegisterUser"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := common.ToUserDoc(user)

	_, err := s.coll.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("%s: failed to register new user: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID, clientID string) error {
	const method = "storage.auth.mongo.MarkEmailVerified"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldID:       userID,
		common.FieldClientID: clientID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	update := bson.M{
		"$set": bson.M{
			common.FieldVerified: true,
		},
	}

	_, err := s.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%s: failed to mark email as verified: %w", method, err)
	}
	return nil
}
