package user

import (
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/service/userdata"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/user/postgres"
)

var (
	ErrPostgresUserStorageSettingsEmpty = fmt.Errorf("postgres user storage settings are empty")
)

func NewStorage(cfg Config) (userdata.Storage, error) {
	switch cfg.Type {
	case StorageTypePostgres:
		return newPostgresStorage(cfg)
	default:
		return nil, fmt.Errorf("unknown user storage type: %s", cfg.Type)
	}
}

func newPostgresStorage(cfg Config) (userdata.Storage, error) {
	if cfg.Postgres == nil {
		return nil, ErrPostgresUserStorageSettingsEmpty
	}

	return postgres.NewUserStorage(cfg.Postgres.Pool), nil
}

type StorageType string

const (
	StorageTypeMongo    StorageType = "mongo"
	StorageTypePostgres StorageType = "postgres"
)

type Config struct {
	Type     StorageType
	Postgres *PostgresParams
}

type PostgresParams struct {
	Pool *pgxpool.Pool
}
