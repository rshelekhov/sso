package postgres

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // Import for side effects
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/storage/postgres/sqlc"
)

// NewStorage creates a new Postgres storage
func NewStorage(cfg *config.ServerSettings) (*pgxpool.Pool, error) {
	const method = "storage.postgres.NewStorage"

	poolCfg, err := pgxpool.ParseConfig(cfg.Postgres.ConnURL)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse config: %w", method, err)
	}

	poolCfg.MaxConnLifetime = cfg.Postgres.IdleTimeout
	poolCfg.MaxConns = int32(cfg.Postgres.ConnPoolSize)

	dialer := &net.Dialer{KeepAlive: cfg.Postgres.DialTimeout}
	dialer.Timeout = cfg.Postgres.DialTimeout
	poolCfg.ConnConfig.DialFunc = dialer.DialContext

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create pgx connection pool: %w", method, err)
	}

	return pool, nil
}

type Store interface {
	sqlc.Querier
}
