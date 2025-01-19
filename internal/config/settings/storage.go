package settings

import (
	"fmt"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	mongoStorage "github.com/rshelekhov/sso/pkg/storage/mongo"
	pgStorage "github.com/rshelekhov/sso/pkg/storage/postgres"
	"time"
)

type StorageType string

const (
	StorageTypeMongo    StorageType = "mongo"
	StorageTypePostgres StorageType = "postgres"
)

type Storage struct {
	Type     StorageType `mapstructure:"DB_TYPE"`
	Mongo    *MongoParams
	Postgres *PostgresParams
}

type MongoParams struct {
	URI    string `mapstructure:"DB_MONGO_URI"`
	DBName string `mapstructure:"DB_MONGO_NAME"`
}

type PostgresParams struct {
	ConnURL      string        `mapstructure:"DB_POSTGRES_CONN_URL"`
	ConnPoolSize int           `mapstructure:"DB_POSTGRES_CONN_POOL_SIZE" envDefault:"10"`
	ReadTimeout  time.Duration `mapstructure:"DB_POSTGRES_READ_TIMEOUT" envDefault:"5s"`
	WriteTimeout time.Duration `mapstructure:"DB_POSTGRES_WRITE_TIMEOUT" envDefault:"5s"`
	IdleTimeout  time.Duration `mapstructure:"DB_POSTGRES_IDLE_TIMEOUT" envDefault:"60s"`
	DialTimeout  time.Duration `mapstructure:"DB_POSTGRES_DIAL_TIMEOUT" envDefault:"10s"`
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
		URI:    params.URI,
		DBName: params.DBName,
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
