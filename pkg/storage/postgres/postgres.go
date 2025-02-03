package postgres

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // Import for side effects
)

func New(cfg *Config) (*pgxpool.Pool, error) {
	const method = "storage.postgres.New"

	poolCfg, err := pgxpool.ParseConfig(cfg.ConnURL)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse config: %w", method, err)
	}

	poolCfg.MaxConnLifetime = cfg.IdleTimeout
	poolCfg.MaxConns = int32(cfg.ConnPoolSize)

	dialer := &net.Dialer{KeepAlive: cfg.DialTimeout}
	dialer.Timeout = cfg.DialTimeout
	poolCfg.ConnConfig.DialFunc = dialer.DialContext

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create pgx connection pool: %w", method, err)
	}

	return pool, nil
}

func Close(pool *pgxpool.Pool) {
	pool.Close()
}

type Config struct {
	ConnURL      string
	ConnPoolSize int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	DialTimeout  time.Duration
}
