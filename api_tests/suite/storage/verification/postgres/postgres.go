package postgres

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TestStorage struct {
	*pgxpool.Pool
}

// NewTestStorage creates a new Postgres storage
func NewTestStorage(pool *pgxpool.Pool) *TestStorage {
	return &TestStorage{
		Pool: pool,
	}
}

func (s *TestStorage) GetToken(ctx context.Context, email string, tokenType entity.VerificationTokenType) (string, error) {
	query := "SELECT token FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var token string
	err := s.Pool.QueryRow(ctx, query, email, int32(tokenType)).Scan(&token)
	if err != nil {
		return "", err
	}

	return token, err
}

func (s *TestStorage) GetTokenExpiresAt(ctx context.Context, email string, tokenType entity.VerificationTokenType) (time.Time, error) {
	query := "SELECT expires_at FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var expiresAt time.Time
	err := s.Pool.QueryRow(ctx, query, email, int32(tokenType)).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, err
	}

	return expiresAt, nil
}

func (s *TestStorage) SetTokenExpired(ctx context.Context, email string, tokenType entity.VerificationTokenType) error {
	query := "UPDATE tokens SET expires_at = $1 WHERE recipient = $2 AND token_type_id = $3"

	expiresAt := time.Now().Add(-24 * time.Hour)
	_, err := s.Pool.Exec(ctx, query, expiresAt, email, int32(tokenType))
	return err
}
