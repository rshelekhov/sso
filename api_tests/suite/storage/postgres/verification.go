package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain/entity"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TestVerificationStorage struct {
	*pgxpool.Pool
}

// NewTestStorage creates a new Postgres storage
func NewTestStorage(pool *pgxpool.Pool) *TestVerificationStorage {
	return &TestVerificationStorage{
		Pool: pool,
	}
}

func (s *TestVerificationStorage) GetToken(ctx context.Context, email string, tokenType entity.VerificationTokenType) (string, error) {
	const method = "api_tests.suite.storage.postgres.verification.GetToken"

	query := "SELECT token FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var token string
	err := s.Pool.QueryRow(ctx, query, email, int32(tokenType)).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("%s: failed to get verification token: %w", method, err)
	}

	return token, err
}

func (s *TestVerificationStorage) GetTokenExpiresAt(ctx context.Context, email string, tokenType entity.VerificationTokenType) (time.Time, error) {
	const method = "api_tests.suite.storage.postgres.verification.GetTokenExpiresAt"

	query := "SELECT expires_at FROM tokens WHERE recipient = $1 AND token_type_id = $2"

	var expiresAt time.Time
	err := s.Pool.QueryRow(ctx, query, email, int32(tokenType)).Scan(&expiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: failed to get verification token expires at: %w", method, err)
	}

	return expiresAt, nil
}

func (s *TestVerificationStorage) SetTokenExpired(ctx context.Context, email string, tokenType entity.VerificationTokenType) error {
	const method = "api_tests.suite.storage.postgres.verification.SetTokenExpired"

	query := "UPDATE tokens SET expires_at = $1 WHERE recipient = $2 AND token_type_id = $3"

	expiresAt := time.Now().Add(-24 * time.Hour)

	if _, err := s.Exec(ctx, query, expiresAt, email, int32(tokenType)); err != nil {
		return fmt.Errorf("%s: failed to set verification token expired: %w", method, err)
	}

	return nil
}
