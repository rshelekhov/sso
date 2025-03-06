package storage

import (
	"fmt"

	mongoStorage "github.com/rshelekhov/sso/pkg/storage/mongo"
	pgStorage "github.com/rshelekhov/sso/pkg/storage/postgres"
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
