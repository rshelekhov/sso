package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
	"github.com/rshelekhov/sso/src/infrastructure/storage/verification/postgres/sqlc"
)

type Storage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewVerificationStorage(pool *pgxpool.Pool) *Storage {
	return &Storage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

func (s *Storage) SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error {
	const method = "verification.postgres.SaveVerificationToken"

	if err := s.Queries.SaveVerificationToken(ctx, sqlc.SaveVerificationTokenParams{
		Token: data.Token,
	}); err != nil {
		return fmt.Errorf("%s: failed to save verification token: %w", method, err)
	}

	return nil
}

func (s *Storage) GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	const method = "verification.postgres.GetTokenData"

	tokenData, err := s.Queries.GetVerificationTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.VerificationToken{}, storage.ErrVerificationTokenNotFound
		}
		return entity.VerificationToken{}, fmt.Errorf("%s: failed to get verification token data: %w", method, err)
	}

	return entity.VerificationToken{
		Token:     tokenData.Token,
		UserID:    tokenData.UserID,
		AppID:     tokenData.AppID,
		Endpoint:  tokenData.Endpoint,
		Email:     tokenData.Recipient,
		Type:      entity.VerificationTokenType(tokenData.TokenTypeID),
		ExpiresAt: tokenData.ExpiresAt,
	}, nil
}

func (s *Storage) DeleteVerificationToken(ctx context.Context, token string) error {
	const method = "verification.postgres.DeleteToken"

	if err := s.Queries.DeleteVerificationToken(ctx, token); err != nil {
		return fmt.Errorf("%s: failed to delete verification token: %w", method, err)
	}

	return nil
}
