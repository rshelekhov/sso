package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/transaction"
	"github.com/rshelekhov/sso/internal/infrastructure/storage/user/postgres/sqlc"
)

type UserStorage struct {
	pool    *pgxpool.Pool
	txMgr   TransactionManager
	queries *sqlc.Queries
}

type TransactionManager interface {
	ExecWithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
}

func NewUserStorage(pool *pgxpool.Pool, txMgr TransactionManager) *UserStorage {
	return &UserStorage{
		pool:    pool,
		txMgr:   txMgr,
		queries: sqlc.New(pool),
	}
}

func (s *UserStorage) GetUserByID(ctx context.Context, appID, userID string) (entity.User, error) {
	const method = "storage.user.postgres.GetUserByID"

	user, err := s.queries.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user: %w", method, err)
	}

	return entity.User{
		ID:        user.ID,
		Email:     user.Email,
		Role:      user.Role,
		AppID:     user.AppID,
		Verified:  user.Verified.Bool,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *UserStorage) GetUserByEmail(ctx context.Context, appID, email string) (entity.User, error) {
	const method = "storage.user.postgres.GetUserByEmail"

	user, err := s.queries.GetUserByEmail(ctx, sqlc.GetUserByEmailParams{
		Email: email,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return entity.User{
		ID:        user.ID,
		Email:     user.Email,
		Role:      user.Role,
		AppID:     user.AppID,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *UserStorage) GetUserData(ctx context.Context, appID, userID string) (entity.User, error) {
	const method = "storage.user.postgres.GetUserData"

	user, err := s.queries.GetUserData(ctx, sqlc.GetUserDataParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return entity.User{
		ID:           user.ID,
		Email:        user.Email,
		Role:         user.Role,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *UserStorage) UpdateUser(ctx context.Context, user entity.User) error {
	const method = "storage.user.postgres.UpdateUser"

	// Prepare the dynamic update query based on the provided fields
	queryUpdate, queryParams := s.buildUpdateUserQuery(user)

	err := s.executeUpdateQuery(ctx, queryUpdate, queryParams)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to execute update query: %w", method, err)
	}

	return nil
}

func (s *UserStorage) buildUpdateUserQuery(user entity.User) (string, []interface{}) {
	queryUpdate := "UPDATE users SET updated_at = $1"
	queryParams := []interface{}{user.UpdatedAt}

	if user.Email != "" {
		queryUpdate += ", email = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.Email)
	}

	if user.PasswordHash != "" {
		queryUpdate += ", password_hash = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.PasswordHash)
	}

	queryUpdate += " WHERE id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.ID)

	queryUpdate += " AND app_id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.AppID)

	return queryUpdate, queryParams
}

func (s *UserStorage) executeUpdateQuery(ctx context.Context, query string, params []interface{}) error {
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, params...)
		return err
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		_, err = s.pool.Exec(ctx, query, params...)
	}

	return err
}

func (s *UserStorage) DeleteUser(ctx context.Context, user entity.User) error {
	const method = "storage.user.postgres.DeleteUser"

	params := sqlc.DeleteUserParams{
		ID:    user.ID,
		AppID: user.AppID,
		DeletedAt: pgtype.Timestamptz{
			Time:  user.DeletedAt,
			Valid: true,
		},
	}

	err := s.executeDeleteUser(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to delete user: %w", method, err)
	}

	return nil
}

func (s *UserStorage) executeDeleteUser(ctx context.Context, params sqlc.DeleteUserParams) error {
	err := s.txMgr.ExecWithinTx(ctx, func(tx pgx.Tx) error {
		return s.queries.WithTx(tx).DeleteUser(ctx, params)
	})

	if errors.Is(err, transaction.ErrTransactionNotFoundInCtx) {
		err = s.queries.DeleteUser(ctx, params)
	}

	return err
}

// GetUserStatusByEmail returns the status of the user with the given email
func (s *UserStorage) GetUserStatusByEmail(ctx context.Context, appID, email string) (string, error) {
	const method = "storage.user.postgres.GetUserStatusByEmail"

	params := sqlc.GetUserStatusByEmailParams{
		Email: email,
		AppID: appID,
	}

	status, err := s.queries.GetUserStatusByEmail(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// GetUserStatusByID returns the status of the user with the given userID
func (s *UserStorage) GetUserStatusByID(ctx context.Context, appID, userID string) (string, error) {
	const method = "storage.user.postgres.GetUserStatusByID"

	params := sqlc.GetUserStatusByIDParams{
		ID:    userID,
		AppID: appID,
	}

	status, err := s.queries.GetUserStatusByID(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}
