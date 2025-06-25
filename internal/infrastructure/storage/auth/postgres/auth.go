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
	txMgr   TransactionManager
	queries *sqlc.Queries
}

type TransactionManager interface {
	ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
}

func NewAuthStorage(pool *pgxpool.Pool, txMgr TransactionManager) *AuthStorage {
	queries := sqlc.New(pool)

	return &AuthStorage{
		pool:    pool,
		txMgr:   txMgr,
		queries: queries,
	}
}

// ReplaceSoftDeletedUser replaces a soft deleted user with the given user
func (s *AuthStorage) ReplaceSoftDeletedUser(ctx context.Context, user entity.User) error {
	const method = "storage.auth.postgres.ReplaceSoftDeletedUser"

	params := sqlc.ReplaceSoftDeletedUserParams{
		ID:           user.ID,
		PasswordHash: user.PasswordHash,
		Verified: pgtype.Bool{
			Bool:  user.Verified,
			Valid: true,
		},
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	// Save user within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).ReplaceSoftDeletedUser(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Save user without transaction
		err = s.queries.ReplaceSoftDeletedUser(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to replace soft deleted user: %w", method, err)
	}

	return nil
}

// RegisterUser creates a new user
func (s *AuthStorage) RegisterUser(ctx context.Context, user entity.User) error {
	const method = "storage.auth.postgres.RegisterUser"

	params := sqlc.RegisterUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
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

func (s *AuthStorage) MarkEmailVerified(ctx context.Context, userID string) error {
	const method = "storage.auth.postgres.MarkEmailVerified"

	// Mark email as verified within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).MarkEmailVerified(ctx, userID)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Mark email as verified without transaction
		err = s.queries.MarkEmailVerified(ctx, userID)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to mark email as verified: %w", method, err)
	}

	return nil
}
