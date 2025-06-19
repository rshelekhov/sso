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

type ClientStorage struct {
	coll    *mongo.Collection
	timeout time.Duration
}

const clientsCollectionName = "clients"

func NewClientStorage(db *mongo.Database, timeout time.Duration) (*ClientStorage, error) {
	const op = "storage.client.mongo.NewClientStorage"

	if db == nil {
		return nil, fmt.Errorf("%s: database connection is nil", op)
	}

	if timeout <= 0 {
		return nil, fmt.Errorf("%s: ivnalid timeout value: %v", op, timeout)
	}

	coll := db.Collection(clientsCollectionName)

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

	return &ClientStorage{
		coll:    coll,
		timeout: timeout,
	}, nil
}

func (s *ClientStorage) RegisterClient(ctx context.Context, data entity.ClientData) error {
	const method = "storage.client.mongo.RegisterClient"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	doc := toClientDoc(data)

	if _, err := s.coll.InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrClientAlreadyExists
		}
		return fmt.Errorf("%s: failed to register client: %w", method, err)
	}

	return nil
}

func (s *ClientStorage) DeleteClient(ctx context.Context, data entity.ClientData) error {
	const method = "storage.client.mongo.DeleteClient"

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
			return storage.ErrClientNotFound
		}
		return fmt.Errorf("%s: failed to delete app: %w", method, err)
	}

	return nil
}

func (s *ClientStorage) CheckClientIDExists(ctx context.Context, clientID string) error {
	const method = "storage.client.mongo.CheckClientIDExists"

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filter := bson.M{
		fieldID:        clientID,
		fieldDeletedAt: nil,
	}

	opts := options.FindOne().SetProjection(bson.M{"_id": 1})

	result := s.coll.FindOne(ctx, filter, opts)

	if err := result.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storage.ErrClientIDDoesNotExist
		}
		return fmt.Errorf("%s: failed to check if client ID exists: %w", method, err)
	}

	return nil
}
