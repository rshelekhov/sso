package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage/mongo/common"
	mongoStorage "github.com/rshelekhov/sso/pkg/storage/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Mongo struct {
	Database *mongo.Database
	Client   *mongo.Client
	Timeout  time.Duration
}

func newMongoStorage(cfg Config) (*DBConnection, error) {
	const method = "storage.newMongoStorage"

	db, err := mongoStorage.New(cfg.Mongo)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new mongodb storage: %w", method, err)
	}

	if err = initializeCollection(db.Database); err != nil {
		return nil, fmt.Errorf("%s: failed to initialize collections: %w", method, err)
	}

	return &DBConnection{
		Type: TypeMongo,
		Mongo: &Mongo{
			Database: db.Database,
			Client:   db.Client,
			Timeout:  db.Timeout,
		},
	}, nil
}

func initializeCollection(db *mongo.Database) error {
	if err := createUserIndexes(db); err != nil {
		return err
	}
	return nil
}

func createUserIndexes(db *mongo.Database) error {
	coll := db.Collection(common.UsersCollectionName)

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: common.FieldAppID, Value: 1},
				{Key: common.FieldID, Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			// Email should be unique for active (not soft-deleted) users
			Keys: bson.D{
				{Key: common.FieldAppID, Value: 1},
				{Key: common.FieldEmail, Value: 1},
			},
			Options: options.Index().
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{
						Key:   common.FieldDeletedAt,
						Value: bson.D{{Key: "$eq", Value: nil}},
					},
				}),
		},
	}

	_, err := coll.Indexes().CreateMany(context.Background(), indexes)
	if err != nil {
		return fmt.Errorf("failed to create user indexes: %w", err)
	}

	return nil
}
