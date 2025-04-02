package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/mongo/common"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RBACStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewRBACStorage(db *mongo.Database, timeout time.Duration) (*RBACStorage, error) {
	const op = "storage.rbac.mongo.NewRBACStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: invalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(common.UsersCollectionName)

	return &RBACStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *RBACStorage) GetUserRole(ctx context.Context, appID, userID string) (string, error) {
	const method = "storage.user.mongo.GetUserRole"

	filter := bson.M{
		common.FieldAppID: appID,
		common.FieldID:    userID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	opts := options.FindOne().SetProjection(bson.M{
		common.FieldRole: 1,
	})

	result := s.coll.FindOne(ctx, filter, opts)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to get user role: %w", method, err)
	}

	var doc common.UserDocument
	if err := result.Decode(&doc); err != nil {
		return "", fmt.Errorf("%s: failed to decode user role: %w", method, err)
	}

	return doc.Role, nil
}

func (s *RBACStorage) SetUserRole(ctx context.Context, appID, userID, role string) error {
	const method = "storage.user.mongo.SetUserRole"

	filter := bson.M{
		common.FieldID:    userID,
		common.FieldAppID: appID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	update := bson.M{
		"$set": bson.M{
			common.FieldRole: role,
		},
	}

	result, err := s.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%s: failed to set user role: %w", method, err)
	}

	if result.MatchedCount == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}
