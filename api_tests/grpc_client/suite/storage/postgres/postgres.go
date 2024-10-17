package postgres

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/model"
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

func (s *TestStorage) GetToken(ctx context.Context, email string, tokenType model.TokenType) (string, error) {
	query := "SELECT token FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var token string
	err := s.Pool.QueryRow(ctx, query, email, int32(tokenType)).Scan(&token)
	if err != nil {
		return "", err
	}

	return token, err
}

func (s *TestStorage) GetTokenExpiresAt(ctx context.Context, email string, tokenType model.TokenType) (time.Time, error) {
	query := "SELECT expires_at FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var expiresAt time.Time
	err := s.Pool.QueryRow(ctx, query, email, int32(tokenType)).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, err
	}

	return expiresAt, nil
}

func (s *TestStorage) SetTokenExpired(ctx context.Context, email string, tokenType model.TokenType) error {
	query := "UPDATE tokens SET expires_at = $1 WHERE recipient = $2 AND token_type_id = $3"

	expiresAt := time.Now().Add(-24 * time.Hour)
	_, err := s.Pool.Exec(ctx, query, expiresAt, email, int32(tokenType))
	return err
}
