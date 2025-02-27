package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AppStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

const appsCollectionName = "applications"

func NewAppStorage(db *mongo.Database, timeout time.Duration) (*AppStorage, error) {
	const op = "storage.app.mongo.NewAppStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(appsCollectionName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create index to ensure uniqueness
	// App name should be unique
	model := mongo.IndexModel{
		Keys:    bson.D{{fieldName, 1}},
		Options: options.Index().SetUnique(true),
	}

	_, err := coll.Indexes().CreateOne(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create index: %w", op, err)
	}

	return &AppStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *AppStorage) RegisterApp(ctx context.Context, data entity.AppData) error {
	const method = "storage.app.mongo.RegisterApp"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := toAppDoc(data)

	if _, err := s.coll.InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAppAlreadyExists
		}
		return fmt.Errorf("%s: failed to register app: %w", method, err)
	}

	return nil
}

func (s *AppStorage) DeleteApp(ctx context.Context, data entity.AppData) error {
	const method = "storage.app.mongo.DeleteApp"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldID:        data.ID,
		fieldSecret:    data.Secret,
		fieldDeletedAt: nil,
	}

	update := bson.M{
		"$set": bson.M{
			fieldDeletedAt: data.DeletedAt,
		},
	}

	result := s.coll.FindOneAndUpdate(ctx, filter, update)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storage.ErrAppNotFound
		}
		return fmt.Errorf("%s: failed to delete app: %w", method, err)
	}

	return nil
}

func (s *AppStorage) CheckAppIDExists(ctx context.Context, appID string) error {
	const method = "storage.app.mongo.CheckAppIDExists"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldID:        appID,
		fieldDeletedAt: nil,
	}

	opts := options.FindOne().SetProjection(bson.M{"_id": 1})

	result := s.coll.FindOne(ctx, filter, opts)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storage.ErrAppIDDoesNotExist
		}
		return fmt.Errorf("%s: failed to check if app ID exists: %w", method, err)
	}

	return nil
}
