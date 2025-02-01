package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/auth/postgres/sqlc"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
)

type AuthStorage struct {
	pool    *pgxpool.Pool
	txMgr   transaction.PostgresManager
	queries *sqlc.Queries
}

func NewAuthStorage(pool *pgxpool.Pool, txMgr transaction.PostgresManager) *AuthStorage {
	return &AuthStorage{
		pool:    pool,
		txMgr:   txMgr,
		queries: sqlc.New(pool),
	}
}

// ReplaceSoftDeletedUser replaces a soft deleted user with the given user
func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	const method = "auth.postgres.ReplaceSoftDeletedUser"

	params := sqlc.RegisterUserParams{
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
	}

	// Save user within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).RegisterUser(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Save user without transaction
		err = s.queries.RegisterUser(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to replace soft deleted user: %w", method, err)
	}

	return nil
}

// RegisterUser creates a new user
func (s *AuthStorage) RegisterUser(ctx context.Context, user entity.User) error {
	const method = "auth.postgres.RegisterUser"

	params := sqlc.RegisterUserParams{
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
	}

	// Save user within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).RegisterUser(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Save user without transaction
		err = s.queries.RegisterUser(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to register new user: %w", method, err)
	}

	return nil
}

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID, appID string) error {
	const method = "auth.postgres.MarkEmailVerified"

	params := sqlc.MarkEmailVerifiedParams{
		ID:    userID,
		AppID: appID,
	}

	// Mark email as verified within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).MarkEmailVerified(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Mark email as verified without transaction
		err = s.queries.MarkEmailVerified(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to mark email as verified: %w", method, err)
	}

	return nil
}
