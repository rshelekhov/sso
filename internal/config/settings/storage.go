package settings

import (
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/pkg/storage/mongo"
	pgStorage "github.com/rshelekhov/sso/pkg/storage/postgres"
)

type StorageType string

const (
	StorageTypeMongo    StorageType = "mongo"
	StorageTypePostgres StorageType = "postgres"
)

type Storage struct {
	Type     StorageType     `yaml:"Type"`
	Mongo    *MongoParams    `yaml:"Mongo"`
	Postgres *PostgresParams `yaml:"Postgres"`
}

type MongoParams struct {
	URI     string        `yaml:"URI"`
	DBName  string        `yaml:"DBName"`
	Timeout time.Duration `yaml:"Timeout" default:"30s"`
}

type PostgresParams struct {
	ConnURL      string        `yaml:"ConnURL"`
	ConnPoolSize int           `yaml:"ConnPoolSize" default:"10"`
	ReadTimeout  time.Duration `yaml:"ReadTimeout" default:"5s"`
	WriteTimeout time.Duration `yaml:"WriteTimeout" default:"5s"`
	IdleTimeout  time.Duration `yaml:"IdleTimeout" default:"60s"`
	DialTimeout  time.Duration `yaml:"DialTimeout" default:"10s"`
}

func ToStorageConfig(s Storage) (storage.Config, error) {
	const op = "settings.Storage.ToStorageConfig"

	storageType, err := validateAndConvertStorageType(s.Type)
	if err != nil {
		return storage.Config{}, fmt.Errorf("%s: %w", op, err)
	}

	return storage.Config{
		Type:     storageType,
		Mongo:    convertMongoParams(s.Mongo),
		Postgres: convertPostgresParams(s.Postgres),
	}, nil
}

func validateAndConvertStorageType(storageType StorageType) (storage.Type, error) {
	switch storageType {
	case StorageTypeMongo:
		return storage.TypeMongo, nil
	case StorageTypePostgres:
		return storage.TypePostgres, nil
	case "":
		return "", fmt.Errorf("storage type is empty")
	default:
		return "", fmt.Errorf("unknown storage type: %s", storageType)
	}
}

func convertMongoParams(params *MongoParams) *mongoStorage.Config {
	if params == nil {
		return nil
	}

	return &mongoStorage.Config{
		URI:     params.URI,
		DBName:  params.DBName,
		Timeout: params.Timeout,
	}
}

func convertPostgresParams(params *PostgresParams) *pgStorage.Config {
	if params == nil {
		return nil
	}

	return &pgStorage.Config{
		ConnURL:      params.ConnURL,
		ConnPoolSize: params.ConnPoolSize,
		ReadTimeout:  params.ReadTimeout,
		WriteTimeout: params.WriteTimeout,
		IdleTimeout:  params.IdleTimeout,
		DialTimeout:  params.DialTimeout,
	}
}
