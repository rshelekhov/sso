package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/model"
	"net"
)

type TestStorage struct {
	*pgxpool.Pool
}

// NewTestStorage creates a new Postgres storage
func NewTestStorage(cfg *config.ServerSettings) (*TestStorage, error) {
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

	return &TestStorage{
		Pool: pool,
	}, nil
}

func (s *TestStorage) GetVerificationToken(ctx context.Context, email string) (string, error) {
	query := "SELECT token FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var token string
	err := s.Pool.QueryRow(ctx, query, email, int32(model.TokenTypeVerifyEmail)).Scan(&token)
	if err != nil {
		return "", err
	}

	return token, err
}
