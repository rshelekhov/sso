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

func (s *UserStorage) GetUserByID(ctx context.Context, userID string) (entity.User, error) {
	const method = "storage.user.mongo.GetUserByID"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldID: userID,
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

func (s *UserStorage) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	const method = "storage.user.mongo.GetUserByEmail"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldEmail: email,
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

func (s *UserStorage) GetUserData(ctx context.Context, userID string) (entity.User, error) {
	const method = "storage.user.mongo.GetUserData"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldID: userID,
		common.FieldDeletedAt: bson.M{
			"$exists": false,
		},
	}

	opts := options.FindOne().SetProjection(bson.M{
		common.FieldID:           1,
		common.FieldEmail:        1,
		common.FieldPasswordHash: 1,
		common.FieldName:         1,
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
		common.FieldID: user.ID,
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
	if user.Name != "" {
		update[common.FieldName] = user.Name
	}

	return update
}

func (s *UserStorage) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	const method = "storage.user.mongo.GetUserStatusByEmail"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Check active user
	filter := bson.M{
		common.FieldEmail: email,
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
		common.FieldEmail: email,
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

func (s *UserStorage) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	const method = "storage.user.mongo.GetUserStatusByID"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Check active user
	filter := bson.M{
		common.FieldID: userID,
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
		common.FieldID: userID,
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
		common.FieldID: user.ID,
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

// SearchUsers searches for users matching the query with cursor-based pagination.
// Returns up to limit users. Use cursorCreatedAt and cursorID for pagination.
func (s *UserStorage) SearchUsers(
	ctx context.Context,
	query string,
	limit int32,
	cursorCreatedAt *time.Time,
	cursorID *string,
) ([]entity.User, error) {
	const method = "storage.user.mongo.SearchUsers"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Build base filter for active users matching search query
	filter := bson.M{
		common.FieldDeletedAt: bson.M{"$exists": false},
		"$or": []bson.M{
			{common.FieldEmail: bson.M{"$regex": query, "$options": "i"}},
			{common.FieldName: bson.M{"$regex": query, "$options": "i"}},
		},
	}

	// Add cursor filter if provided
	if cursorCreatedAt != nil && cursorID != nil {
		// Lexicographic comparison: (created_at, _id) < (cursor_created_at, cursor_id)
		cursorFilter := bson.M{
			"$or": []bson.M{
				{common.FieldCreatedAt: bson.M{"$lt": *cursorCreatedAt}},
				{
					common.FieldCreatedAt: *cursorCreatedAt,
					common.FieldID:        bson.M{"$lt": *cursorID},
				},
			},
		}

		// Combine with existing filter using $and
		filter = bson.M{
			"$and": []bson.M{
				{
					common.FieldDeletedAt: bson.M{"$exists": false},
					"$or": []bson.M{
						{common.FieldEmail: bson.M{"$regex": query, "$options": "i"}},
						{common.FieldName: bson.M{"$regex": query, "$options": "i"}},
					},
				},
				cursorFilter,
			},
		}
	}

	// Set sort order and limit
	opts := options.Find().
		SetSort(bson.D{
			{Key: common.FieldCreatedAt, Value: -1}, // DESC
			{Key: common.FieldID, Value: -1},        // DESC
		}).
		SetLimit(int64(limit))

	cursor, err := s.coll.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to search users: %w", method, err)
	}
	defer cursor.Close(ctx)

	var docs []common.UserDocument
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("%s: failed to decode users: %w", method, err)
	}

	// Convert to entity.User slice
	users := make([]entity.User, len(docs))
	for i, doc := range docs {
		users[i] = common.ToUserEntity(doc)
	}

	return users, nil
}

// CountSearchUsers returns the total count of users matching the query.
func (s *UserStorage) CountSearchUsers(
	ctx context.Context,
	query string,
) (int32, error) {
	const method = "storage.user.mongo.CountSearchUsers"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		common.FieldDeletedAt: bson.M{"$exists": false},
		"$or": []bson.M{
			{common.FieldEmail: bson.M{"$regex": query, "$options": "i"}},
			{common.FieldName: bson.M{"$regex": query, "$options": "i"}},
		},
	}

	count, err := s.coll.CountDocuments(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("%s: failed to count search users: %w", method, err)
	}

	return int32(count), nil
}
