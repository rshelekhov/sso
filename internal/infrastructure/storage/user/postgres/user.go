package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
	"github.com/rshelekhov/sso/src/infrastructure/storage/user/postgres/sqlc"
	"strconv"
)

type Storage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewUserStorage(pool *pgxpool.Pool) *Storage {
	return &Storage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

func (s *Storage) GetUserByID(ctx context.Context, appID, userID string) (entity.User, error) {
	const method = "user.postgres.GetUserByID"

	user, err := s.Queries.GetUserByID(ctx, sqlc.GetUserByIDParams{
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
		Email:     user.Email,
		AppID:     user.AppID,
		Verified:  user.Verified.Bool,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *Storage) GetUserByEmail(ctx context.Context, appID, email string) (entity.User, error) {
	const method = "user.postgres.GetUserByEmail"

	user, err := s.Queries.GetUserByEmail(ctx, sqlc.GetUserByEmailParams{
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
		AppID:     user.AppID,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *Storage) GetUserData(ctx context.Context, appID, userID string) (entity.User, error) {
	const method = "user.postgres.GetUserData"

	user, err := s.Queries.GetUserData(ctx, sqlc.GetUserDataParams{
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
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *Storage) UpdateUser(ctx context.Context, user entity.User) error {
	const method = "user.postgres.UpdateUser"

	// Prepare the dynamic update query based on the provided fields
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

	// Add condition for the specific user ID
	queryUpdate += " WHERE id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.ID)

	// Add condition for the specific app ID
	queryUpdate += " AND app_id = $" + strconv.Itoa(len(queryParams)+1)
	queryParams = append(queryParams, user.AppID)

	// Execute the update query
	_, err := s.Exec(ctx, queryUpdate, queryParams...)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to execute update query: %w", method, err)
	}

	return nil
}

func (s *Storage) DeleteUser(ctx context.Context, user entity.User) error {
	const method = "user.postgres.DeleteUser"

	if err := s.Queries.DeleteUser(ctx, sqlc.DeleteUserParams{
		ID:    user.ID,
		AppID: user.AppID,
		DeletedAt: pgtype.Timestamptz{
			Time:  user.DeletedAt,
			Valid: true,
		},
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to delete user: %w", method, err)
	}

	return nil
}

// GetUserStatusByEmail returns the status of the user with the given email
func (s *Storage) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	const method = "user.postgres.GetUserStatusByEmail"

	status, err := s.Queries.GetUserStatusByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// GetUserStatusByID returns the status of the user with the given userID
func (s *Storage) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	const method = "user.postgres.GetUserStatusByID"

	status, err := s.Queries.GetUserStatusByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

func (s *Storage) DeleteAllTokens(ctx context.Context, appID, userID string) error {
	const method = "user.postgres.DeleteAllTokens"

	if err := s.Queries.DeleteAllTokens(ctx, sqlc.DeleteAllTokensParams{
		UserID: userID,
		AppID:  appID,
	}); err != nil {
		return fmt.Errorf("%s: failed to delete tokens: %w", method, err)
	}

	return nil
}
