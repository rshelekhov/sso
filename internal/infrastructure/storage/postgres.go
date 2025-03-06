package storage

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	pgStorage "github.com/rshelekhov/sso/pkg/storage/postgres"
)

type Postgres struct {
	Pool *pgxpool.Pool
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
