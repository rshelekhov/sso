package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/auth/postgres/sqlc"
)

type AuthStorage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewAuthStorage(pool *pgxpool.Pool) *AuthStorage {
	return &AuthStorage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

func (s *AuthStorage) Transaction(ctx context.Context, fn func(storage *AuthStorage) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				err = fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
			}
		} else {
			err = tx.Commit(ctx)
		}
	}()

	err = fn(s)

	return err
}

// ReplaceSoftDeletedUser replaces a soft deleted user with the given user
func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	const method = "auth.postgres.ReplaceSoftDeletedUser"

	if err := s.Queries.RegisterUser(ctx, sqlc.RegisterUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		Verified: pgtype.Bool{
			Bool:  user.Verified,
			Valid: true,
		},
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to replace soft deleted user: %w", method, err)
	}
	return nil
}

// RegisterUser creates a new user
func (s *AuthStorage) RegisterUser(ctx context.Context, user entity.User) error {
	const method = "auth.postgres.insertNewUser"

	if err := s.Queries.RegisterUser(ctx, sqlc.RegisterUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		Verified: pgtype.Bool{
			Bool:  user.Verified,
			Valid: true,
		},
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to insert new user: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID, appID string) error {
	const method = "auth.postgres.MarkEmailVerified"

	if err := s.Queries.MarkEmailVerified(ctx, sqlc.MarkEmailVerifiedParams{
		ID:    userID,
		AppID: appID,
	}); err != nil {
		return fmt.Errorf("%s: failed to mark email as verified: %w", method, err)
	}

	return nil
}
