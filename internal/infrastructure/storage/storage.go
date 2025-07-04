package storage

import (
	"context"
	"fmt"
	"time"

	mongoLib "github.com/rshelekhov/golib/db/mongo"
	postgresLib "github.com/rshelekhov/golib/db/postgres/pgxv5"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/mongo/common"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DBConnection struct {
	Type     Type
	Mongo    *Mongo
	Postgres *Postgres
}

type Type string

const (
	TypeMongo    Type = "mongo"
	TypePostgres Type = "postgres"
)

type Mongo struct {
	*mongoLib.Connection
	Timeout time.Duration
}

type Postgres struct {
	*postgresLib.Connection
}

func NewDBConnection(ctx context.Context, cfg settings.Storage) (*DBConnection, error) {
	switch cfg.Type {
	case settings.StorageTypeMongo:
		return newMongoStorage(ctx, cfg.Mongo)
	case settings.StorageTypePostgres:
		return newPostgresStorage(ctx, cfg.Postgres)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Type)
	}
}

func newMongoStorage(ctx context.Context, cfg *settings.MongoParams) (*DBConnection, error) {
	const method = "storage.newMongoStorage"

	conn, err := mongoLib.NewConnection(ctx, cfg.URI, cfg.DBName)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new mongodb storage: %w", method, err)
	}

	if err = initializeCollection(conn.Database()); err != nil {
		return nil, fmt.Errorf("%s: failed to initialize collections: %w", method, err)
	}

	return &DBConnection{
		Type: TypeMongo,
		Mongo: &Mongo{
			Connection: conn.(*mongoLib.Connection),
			Timeout:    cfg.Timeout,
		},
	}, nil
}

func newPostgresStorage(ctx context.Context, cfg *settings.PostgresParams) (*DBConnection, error) {
	const method = "storage.newPostgresStorage"

	conn, err := postgresLib.NewConnectionPool(ctx, cfg.ConnURL)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new postgres storage: %w", method, err)
	}

	return &DBConnection{
		Type: TypePostgres,
		Postgres: &Postgres{
			Connection: conn,
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
				{Key: common.FieldClientID, Value: 1},
				{Key: common.FieldID, Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			// Email should be unique for active (not soft-deleted) users
			Keys: bson.D{
				{Key: common.FieldClientID, Value: 1},
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

func (d *DBConnection) Close(ctx context.Context) error {
	const method = "storage.DBConnection.Close"

	switch d.Type {
	case TypeMongo:
		return d.Mongo.Close(ctx)
	case TypePostgres:
		d.Postgres.Close()
		return nil
	default:
		return fmt.Errorf("%s: unknown storage type: %s", method, d.Type)
	}
}
