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

// NewStorage creates a new storage
func NewStorage(cfg *config.ServerSettings) (*pgxpool.Pool, error) {
	const method = "storage.postgres.NewStorage"

	poolCfg, err := pgxpool.ParseConfig(cfg.Storage.ConnURL)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse config: %w", method, err)
	}

	poolCfg.MaxConnLifetime = cfg.Storage.IdleTimeout
	poolCfg.MaxConns = int32(cfg.Storage.ConnPoolSize)

	dialer := &net.Dialer{KeepAlive: cfg.Storage.DialTimeout}
	dialer.Timeout = cfg.Storage.DialTimeout
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
