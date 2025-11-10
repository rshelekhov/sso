package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

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

func (s *UserStorage) GetUserByID(ctx context.Context, userID string) (entity.User, error) {
	const method = "storage.user.postgres.GetUserByID"

	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user: %w", method, err)
	}

	return entity.User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Verified:  user.Verified.Bool,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *UserStorage) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	const method = "storage.user.postgres.GetUserByEmail"

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return entity.User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *UserStorage) GetUserData(ctx context.Context, userID string) (entity.User, error) {
	const method = "storage.user.postgres.GetUserData"

	user, err := s.queries.GetUserData(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.User{}, storage.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return entity.User{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		PasswordHash: user.PasswordHash,
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

func (s *UserStorage) buildUpdateUserQuery(user entity.User) (string, []any) {
	queryUpdate := "UPDATE users SET updated_at = $1"
	queryParams := []any{user.UpdatedAt}

	if user.Email != "" {
		queryUpdate += ", email = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.Email)
	}

	if user.PasswordHash != "" {
		queryUpdate += ", password_hash = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.PasswordHash)
	}

	if user.Name != "" {
		queryUpdate += ", name = $" + strconv.Itoa(len(queryParams)+1)
		queryParams = append(queryParams, user.Name)
	}

	queryUpdate += " WHERE id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.ID)

	return queryUpdate, queryParams
}

func (s *UserStorage) executeUpdateQuery(ctx context.Context, query string, params []any) error {
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
		ID: user.ID,
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
func (s *UserStorage) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	const method = "storage.user.postgres.GetUserStatusByEmail"

	status, err := s.queries.GetUserStatusByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// GetUserStatusByID returns the status of the user with the given userID
func (s *UserStorage) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	const method = "storage.user.postgres.GetUserStatusByID"

	status, err := s.queries.GetUserStatusByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// SearchUsers searches for users matching the query with cursor-based pagination.
// Returns up to limit users. Use cursorCreatedAt and cursorID for pagination.
func (s *UserStorage) SearchUsers(
	ctx context.Context,
	query string,
	limit int32,
	cursorCreatedAt *time.Time,
	cursorID *string,
) ([]entity.User, error) {
	const method = "storage.user.postgres.SearchUsers"

	// Build sqlc params
	params := sqlc.SearchUsersParams{
		Query:    query,
		PageSize: limit,
	}

	// Add cursor params if provided
	if cursorCreatedAt != nil {
		params.CursorCreatedAt = pgtype.Timestamptz{
			Time:  *cursorCreatedAt,
			Valid: true,
		}
	}
	if cursorID != nil {
		params.CursorID = pgtype.Text{
			String: *cursorID,
			Valid:  true,
		}
	}

	rows, err := s.queries.SearchUsers(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to search users: %w", method, err)
	}

	// Convert to entity.User slice
	users := make([]entity.User, len(rows))
	for i, row := range rows {
		users[i] = entity.User{
			ID:        row.ID,
			Email:     row.Email,
			Name:      row.Name,
			Verified:  row.Verified.Bool,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}
	}

	return users, nil
}

// CountSearchUsers returns the total count of users matching the query.
func (s *UserStorage) CountSearchUsers(
	ctx context.Context,
	query string,
) (int32, error) {
	const method = "storage.user.postgres.CountSearchUsers"

	count, err := s.queries.CountSearchUsers(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("%s: failed to count search users: %w", method, err)
	}

	return int32(count), nil
}
