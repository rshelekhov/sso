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
	coll := db.Collection(appsCollectionName)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create index to ensure uniqueness
	// App name should be unique
	if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{"name", 1}},
		Options: options.Index().SetUnique(true),
	}); err != nil {
		return nil, fmt.Errorf("failed to create index: %w", err)
	}

	return &AppStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *AppStorage) RegisterApp(ctx context.Context, data entity.AppData) error {
	const method = "storage.app.mongo.RegisterApp"

	appDoc := toAppDoc(data)

	_, err := s.coll.InsertOne(ctx, appDoc)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAppAlreadyExists
		}
		return fmt.Errorf("%s: failed to register app: %w", method, err)
	}

	return nil
}

func (s *AppStorage) DeleteApp(ctx context.Context, data entity.AppData) error {
	const method = "storage.app.mongo.DeleteApp"

	filter := bson.M{
		"_id":        data.ID,
		"secret":     data.Secret,
		"deleted_at": nil,
	}

	update := bson.M{
		"$set": bson.M{
			"deleted_at": data.DeletedAt,
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

	filter := bson.M{
		"_id":        appID,
		"deleted_at": nil,
	}

	count, err := s.coll.CountDocuments(ctx, filter)
	if err != nil {
		return fmt.Errorf("%s: failed to check if app ID exists: %w", method, err)
	}

	if count == 0 {
		return storage.ErrAppIDDoesNotExist
	}

	return nil
}
