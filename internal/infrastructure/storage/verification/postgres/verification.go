package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/verification/postgres/sqlc"
)

type VerificationStorage struct {
	pool    *pgxpool.Pool
	txMgr   TransactionManager
	queries *sqlc.Queries
}

type TransactionManager interface {
	ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
}

func NewVerificationStorage(pool *pgxpool.Pool, txMgr TransactionManager) *VerificationStorage {
	return &VerificationStorage{
		pool:    pool,
		txMgr:   txMgr,
		queries: sqlc.New(pool),
	}
}

func (s *VerificationStorage) SaveVerificationToken(ctx context.Context, data entity.VerificationToken) error {
	const method = "storage.verification.postgres.SaveVerificationToken"

	params := sqlc.SaveVerificationTokenParams{
		Token:       data.Token,
		UserID:      data.UserID,
		ClientID:    data.ClientID,
		Endpoint:    data.Endpoint,
		Recipient:   data.Email,
		TokenTypeID: int32(data.Type),
		CreatedAt:   data.CreatedAt,
		ExpiresAt:   data.ExpiresAt,
	}

	// Save verification token within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).SaveVerificationToken(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Save verification token without transaction
		err = s.queries.SaveVerificationToken(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to save verification token: %w", method, err)
	}

	return nil
}

func (s *VerificationStorage) GetVerificationTokenData(ctx context.Context, token string) (entity.VerificationToken, error) {
	const method = "storage.verification.postgres.GetTokenData"

	tokenData, err := s.queries.GetVerificationTokenData(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.VerificationToken{}, storage.ErrVerificationTokenNotFound
		}
		return entity.VerificationToken{}, fmt.Errorf("%s: failed to get verification token data: %w", method, err)
	}

	return entity.VerificationToken{
		Token:     tokenData.Token,
		UserID:    tokenData.UserID,
		ClientID:  tokenData.ClientID,
		Endpoint:  tokenData.Endpoint,
		Email:     tokenData.Recipient,
		Type:      entity.VerificationTokenType(tokenData.TokenTypeID),
		ExpiresAt: tokenData.ExpiresAt,
	}, nil
}

func (s *VerificationStorage) DeleteVerificationToken(ctx context.Context, token string) error {
	const method = "storage.verification.postgres.DeleteToken"

	// Delete verification token within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).DeleteVerificationToken(ctx, token)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Delete verification token without transaction
		err = s.queries.DeleteVerificationToken(ctx, token)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to delete verification token: %w", method, err)
	}

	return nil
}

func (s *VerificationStorage) DeleteAllTokens(ctx context.Context, clientID, userID string) error {
	const method = "storage.verification.postgres.DeleteAllTokens"

	params := sqlc.DeleteAllVerificationTokensParams{
		UserID:   userID,
		ClientID: clientID,
	}

	// Delete verification tokens within transaction
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).DeleteAllVerificationTokens(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		// Delete verification tokens without transaction
		err = s.queries.DeleteAllVerificationTokens(ctx, params)
	}

	if err != nil {
		return fmt.Errorf("%s: failed to delete all verification tokens: %w", method, err)
	}

	return nil
}
