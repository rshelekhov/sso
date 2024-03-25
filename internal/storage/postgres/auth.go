package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/rshelekhov/sso/internal/storage/postgres/sqlc"
	"time"
)

type AuthStorage struct {
	*pgxpool.Pool
	*sqlc.Queries
}

func NewAuthStorage(pool *pgxpool.Pool) port.AuthStorage {
	return &AuthStorage{
		Pool:    pool,
		Queries: sqlc.New(pool),
	}
}

func (s *AuthStorage) Transaction(ctx context.Context, fn func(storage port.AuthStorage) error) error {
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

func (s *AuthStorage) CreateUser(ctx context.Context, user model.User) error {
	const method = "storage.AuthStorage.CreateUser"

	userStatus, err := s.getUserStatus(ctx, user.Email)
	if err != nil {
		return err
	}

	switch userStatus {
	case "active":
		return le.ErrUserAlreadyExists
	case "soft_deleted":
		if err = s.replaceSoftDeletedUser(ctx, user); err != nil {
			return err
		}
	case "not_found":
		if err = s.insertUser(ctx, user); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: unknown user status: %s", method, userStatus)
	}

	return nil
}

// getUserStatus returns the status of the user with the given email
func (s *AuthStorage) getUserStatus(ctx context.Context, email string) (string, error) {
	const method = "user.storage.getUserStatus"

	status, err := s.Queries.GetUserStatus(ctx, email)
	if err != nil {
		return "", fmt.Errorf("%s: failed to check if user exists: %w", method, err)
	}

	return status, nil
}

// replaceSoftDeletedUser replaces a soft deleted user with the given user
func (s *AuthStorage) replaceSoftDeletedUser(ctx context.Context, user model.User) error {
	const method = "user.storage.replaceSoftDeletedUser"

	if err := s.Queries.SetDeletedUserAtNull(ctx, user.Email); err != nil {
		return fmt.Errorf("%s: failed to set deleted_at to NULL: %w", method, err)
	}

	if err := s.Queries.InsertUser(ctx, sqlc.InsertUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		UpdatedAt:    user.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to replace soft deleted user: %w", method, err)
	}
	return nil
}

// insertUser inserts a new user
func (s *AuthStorage) insertUser(ctx context.Context, user model.User) error {
	const method = "user.storage.insertNewUser"

	if err := s.Queries.InsertUser(ctx, sqlc.InsertUserParams{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		UpdatedAt:    user.UpdatedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to insert new user: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	panic("implement me")
}

func (s *AuthStorage) GetUserByID(ctx context.Context, userID string, appID int) (model.User, error) {
	panic("implement me")
}

func (s *AuthStorage) GetUserData(ctx context.Context, userID string) (model.User, error) {
	panic("implement me")
}

func (s *AuthStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	panic("implement me")
}

func (s *AuthStorage) UpdateLastVisitedAt(ctx context.Context, deviceID string, latestLoginAt time.Time) error {
	panic("implement me")
}

func (s *AuthStorage) RegisterDevice(ctx context.Context, device model.UserDevice) error {
	panic("implement me")
}

func (s *AuthStorage) CreateUserSession(ctx context.Context, session model.Session) error {
	panic("implement me")
}

func (s *AuthStorage) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (model.Session, error) {
	panic("implement me")
}

func (s *AuthStorage) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	panic("implement me")
}

func (s *AuthStorage) DeleteSession(ctx context.Context, userID, deviceID string) error {
	panic("implement me")
}

func (s *AuthStorage) CheckEmailUniqueness(ctx context.Context, user model.User) error {
	panic("implement me")
}

func (s *AuthStorage) UpdateUser(ctx context.Context, user model.User) error {
	panic("implement me")
}

func (s *AuthStorage) DeleteUser(ctx context.Context, user model.User) error {
	panic("implement me")
}
