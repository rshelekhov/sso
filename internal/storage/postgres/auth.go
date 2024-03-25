package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
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
	const method = "storage.storage.CreateUser"

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

func (s *AuthStorage) GetUserByEmail(ctx context.Context, email string, appID int32) (model.User, error) {
	const method = "user.storage.GetUserByEmail"

	user, err := s.Queries.GetUserByEmail(ctx, sqlc.GetUserByEmailParams{
		Email: email,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.User{}, le.ErrUserNotFound
		}
		return model.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return model.User{
		ID:        user.ID,
		Email:     user.Email,
		AppID:     user.AppID,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *AuthStorage) GetUserByID(ctx context.Context, userID string, appID int32) (model.User, error) {
	const method = "user.storage.GetUserByID"

	user, err := s.Queries.GetUserByID(ctx, sqlc.GetUserByIDParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.User{}, le.ErrUserNotFound
		}
		return model.User{}, fmt.Errorf("%s: failed to get user: %w", method, err)
	}

	return model.User{
		ID:        user.ID,
		Email:     user.Email,
		AppID:     user.AppID,
		UpdatedAt: user.UpdatedAt,
	}, nil
}

func (s *AuthStorage) GetUserData(ctx context.Context, userID string, appID int32) (model.User, error) {
	const method = "user.storage.GetUserData"

	user, err := s.Queries.GetUserData(ctx, sqlc.GetUserDataParams{
		ID:    userID,
		AppID: appID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.User{}, le.ErrUserNotFound
		}
		return model.User{}, fmt.Errorf("%s: failed to get user credentials: %w", method, err)
	}

	return model.User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		AppID:        user.AppID,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *AuthStorage) GetUserDeviceID(ctx context.Context, userID, userAgent string) (string, error) {
	const method = "user.storage.GetUserDeviceID"

	deviceID, err := s.Queries.GetUserDeviceID(ctx, sqlc.GetUserDeviceIDParams{
		UserID:    userID,
		UserAgent: userAgent,
	})

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", le.ErrUserDeviceNotFound
		}
		return "", fmt.Errorf("%s: failed to get id of user device: %w", method, err)
	}

	return deviceID, nil
}

func (s *AuthStorage) UpdateLastLoginAt(ctx context.Context, deviceID string, appID int32, latestLoginAt time.Time) error {
	const method = "user.storage.UpdateLastLoginAt"

	if err := s.Queries.UpdateLatestLoginAt(ctx, sqlc.UpdateLatestLoginAtParams{
		ID:          deviceID,
		LastLoginAt: latestLoginAt,
		AppID:       appID,
	}); err != nil {
		return fmt.Errorf("%s: failed to update latest login at: %w", method, err)
	}
	return nil
}

func (s *AuthStorage) RegisterDevice(ctx context.Context, device model.UserDevice) error {
	const method = "user.storage.RegisterDevice"

	if err := s.Queries.RegisterDevice(ctx, sqlc.RegisterDeviceParams{
		ID:          device.ID,
		UserID:      device.UserID,
		AppID:       device.AppID,
		UserAgent:   device.UserAgent,
		Ip:          device.IP,
		Detached:    device.Detached,
		LastLoginAt: device.LastVisitedAt,
	}); err != nil {
		return fmt.Errorf("%s: failed to register user device: %w", method, err)
	}

	return nil
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
