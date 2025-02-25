package mongo

import (
	"context"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AuthStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

const authCollectionName = "auth"

func NewAuthStorage(db *mongo.Database, timeout time.Duration) (*AuthStorage, error) {
	const op = "storage.auth.mongo.NewAuthStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(authCollectionName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create index to ensure uniqueness
	// Email should be unique for active (not soft-deleted) users
	model := mongo.IndexModel{
		Keys: bson.D{{"email", 1}},
		Options: options.Index().
			SetUnique(true).
			SetPartialFilterExpression(bson.M{"deleted_at": bson.M{"$exists": false}}),
	}

	_, err := coll.Indexes().CreateOne(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("%s:failed to create index: %w", op, err)
	}

	return &AuthStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	const method = "storage.auth.mongo.ReplaceSoftDeletedUser"

	filter := bson.M{
		"email": user.Email,
		"deleted_at": bson.M{
			"$ne": nil,
		},
	}

	userDoc := toUserDoc(user)

	_, err := s.coll.ReplaceOne(ctx, filter, userDoc)
	if err != nil {
		return fmt.Errorf("%s: failed to replace soft deleted user: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) RegisterUser(ctx context.Context, user entity.User) error {
	const method = "storage.auth.mongo.RegisterUser"

	userDoc := toUserDoc(user)

	_, err := s.coll.InsertOne(ctx, userDoc)
	if err != nil {
		return fmt.Errorf("%s: failed to register new user: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID, appID string) error {
	const method = "storage.auth.mongo.MarkEmailVerified"

	filter := bson.M{
		"_id":    userID,
		"app_id": appID,
		"deleted_at": bson.M{
			"$exists": false,
		},
	}

	update := bson.M{
		"$set": bson.M{
			"verified": true,
		},
	}

	_, err := s.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%s: failed to mark email as verified: %w", method, err)
	}
	return nil
}
