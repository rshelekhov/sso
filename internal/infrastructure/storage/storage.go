package storage

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	mongoStorage "github.com/rshelekhov/sso/pkg/storage/mongo"
	pgStorage "github.com/rshelekhov/sso/pkg/storage/postgres"
	"go.mongodb.org/mongo-driver/mongo"
)

type DBConnection struct {
	Type     Type
	Postgres *Postgres
	Mongo    *Mongo
}

type Type string

const (
	TypeMongo    Type = "mongo"
	TypePostgres Type = "postgres"
)

type Postgres struct {
	Pool *pgxpool.Pool
}

type Mongo struct {
	Database *mongo.Database
	Client   *mongo.Client
	Timeout  time.Duration
}

func NewDBConnection(cfg Config) (*DBConnection, error) {
	switch cfg.Type {
	case TypeMongo:
		return newMongoStorage(cfg)
	case TypePostgres:
		return newPostgresStorage(cfg)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Type)
	}
}

func newMongoStorage(cfg Config) (*DBConnection, error) {
	const method = "storage.newMongoStorage"

	db, err := mongoStorage.New(cfg.Mongo)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new mongodb storage: %w", method, err)
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

func newPostgresStorage(cfg Config) (*DBConnection, error) {
	const method = "storage.newPostgresStorage"

	pool, err := pgStorage.New(cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create new postgres storage: %w", method, err)
	}

	return &DBConnection{
		Type: TypePostgres,
		Postgres: &Postgres{
			Pool: pool,
		},
	}, nil
}

type Config struct {
	Type     Type
	Mongo    *mongoStorage.Config
	Postgres *pgStorage.Config
}

func (d *DBConnection) Close() error {
	const method = "storage.DBConnection.Close"

	switch d.Type {
	case TypeMongo:
		return mongoStorage.Close(d.Mongo.Client)
	case TypePostgres:
		pgStorage.Close(d.Postgres.Pool)
		return nil
	default:
		return fmt.Errorf("%s: unknown storage type: %s", method, d.Type)
	}
}
