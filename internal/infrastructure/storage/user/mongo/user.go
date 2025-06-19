package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/mongo/common"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewUserStorage(db *mongo.Database, timeout time.Duration) (*UserStorage, error) {
	const op = "storage.user.mongo.NewUserStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(common.UsersCollectionName)

	return &UserStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *UserStorage) GetUserByID(ctx context.Context, clientID, userID string) (entity.User, error) {
	const method = "storage.user.mongo.GetUserByID"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldClientID: clientID,
		common.FieldID:       userID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	result := s.coll.FindOne(ctx, filter)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user: %w", method, err)
	}

	var doc common.UserDocument
	if err := result.Decode(&doc); err != nil {
		return entity.User{}, fmt.Errorf("%s: failed to decode user: %w", method, err)
	}

	return common.ToUserEntity(doc), nil
}

func (s *UserStorage) GetUserByEmail(ctx context.Context, clientID, email string) (entity.User, error) {
	const method = "storage.user.mongo.GetUserByEmail"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldClientID: clientID,
		common.FieldEmail:    email,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	result := s.coll.FindOne(ctx, filter)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user: %w", method, err)
	}

	var doc common.UserDocument
	if err := result.Decode(&doc); err != nil {
		return entity.User{}, fmt.Errorf("%s: failed to decode user: %w", method, err)
	}

	return common.ToUserEntity(doc), nil
}

func (s *UserStorage) GetUserData(ctx context.Context, clientID, userID string) (entity.User, error) {
	const method = "storage.user.mongo.GetUserData"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldClientID: clientID,
		common.FieldID:       userID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	opts := options.FindOne().SetProjection(bson.M{
		common.FieldID:           1,
		common.FieldEmail:        1,
		common.FieldPasswordHash: 1,
		common.FieldClientID:     1,
		common.FieldUpdatedAt:    1,
	})

	result := s.coll.FindOne(ctx, filter, opts)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user data: %w", method, err)
	}

	var doc common.UserDocument
	if err := result.Decode(&doc); err != nil {
		return entity.User{}, fmt.Errorf("%s: failed to decode user data: %w", method, err)
	}

	return common.ToUserEntity(doc), nil
}

func (s *UserStorage) UpdateUser(ctx context.Context, user entity.User) error {
	const method = "storage.user.mongo.UpdateUser"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldClientID: user.ClientID,
		common.FieldID:       user.ID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	update := bson.M{
		"$set": buildUpdateFields(user),
	}

	result := s.coll.FindOneAndUpdate(ctx, filter, update)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storage.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to update user: %w", method, err)
	}

	return nil
}

func buildUpdateFields(user entity.User) bson.M {
	update := bson.M{
		common.FieldUpdatedAt: user.UpdatedAt,
	}

	if user.Email != "" {
		update[common.FieldEmail] = user.Email
	}
	if user.PasswordHash != "" {
		update[common.FieldPasswordHash] = user.PasswordHash
	}

	return update
}

func (s *UserStorage) GetUserStatusByEmail(ctx context.Context, clientID, email string) (string, error) {
	const method = "storage.user.mongo.GetUserStatusByEmail"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Check active user
	filter := bson.M{
		common.FieldClientID: clientID,
		common.FieldEmail:    email,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	count, err := s.coll.CountDocuments(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check active user: %w", method, err)
	}
	if count > 0 {
		return entity.UserStatusActive.String(), nil
	}

	// Check soft deleted user
	filter = bson.M{
		common.FieldClientID: clientID,
		common.FieldEmail:    email,
		common.FieldDeletedAt: bson.M{
			"$ne": nil,
		},
	}

	count, err = s.coll.CountDocuments(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check soft-deleted user: %w", method, err)
	}
	if count > 0 {
		return entity.UserStatusSoftDeleted.String(), nil
	}

	return entity.UserStatusNotFound.String(), nil
}

func (s *UserStorage) GetUserStatusByID(ctx context.Context, clientID, userID string) (string, error) {
	const method = "storage.user.mongo.GetUserStatusByID"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Check active user
	filter := bson.M{
		common.FieldClientID: clientID,
		common.FieldID:       userID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	count, err := s.coll.CountDocuments(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check active user: %w", method, err)
	}
	if count > 0 {
		return entity.UserStatusActive.String(), nil
	}

	// Check soft deleted user
	filter = bson.M{
		common.FieldClientID: clientID,
		common.FieldID:       userID,
		common.FieldDeletedAt: bson.M{
			"$ne": nil,
		},
	}

	count, err = s.coll.CountDocuments(ctx, filter)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check soft-deleted user: %w", method, err)
	}
	if count > 0 {
		return entity.UserStatusSoftDeleted.String(), nil
	}

	return entity.UserStatusNotFound.String(), nil
}

func (s *UserStorage) DeleteUser(ctx context.Context, user entity.User) error {
	const method = "storage.user.mongo.DeleteUser"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldID:       user.ID,
		common.FieldClientID: user.ClientID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	update := bson.M{
		"$set": bson.M{
			common.FieldDeletedAt: user.DeletedAt,
		},
	}

	result, err := s.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%s: failed to delete user: %w", method, err)
	}

	if result.MatchedCount == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}
