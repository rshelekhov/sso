package user

import (
	"context"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type User struct {
	storage Storage
}

type Storage interface {
	GetUserByID(ctx context.Context, appID, userID string) (entity.User, error)
	GetUserByEmail(ctx context.Context, appID, email string) (entity.User, error)
	GetUserData(ctx context.Context, appID, userID string) (entity.User, error)
	UpdateUser(ctx context.Context, user entity.User) error
	GetUserStatusByEmail(ctx context.Context, email string) (string, error)
	GetUserStatusByID(ctx context.Context, userID string) (string, error)
	DeleteUser(ctx context.Context, user entity.User) error
	DeleteAllTokens(ctx context.Context, appID, userID string) error
}

func NewService(storage Storage) *User {
	return &User{
		storage: storage,
	}
}

func (u *User) GetUserByID(ctx context.Context, appID, userID string) (entity.User, error) {
	const method = "service.user.GetUserByID"

	user, err := u.storage.GetUserByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: %w", method, err)
	}

	return user, nil
}

func (u *User) GetUserByEmail(ctx context.Context, appID, email string) (entity.User, error) {
	const method = "service.user.GetUserByEmail"

	user, err := u.storage.GetUserByEmail(ctx, appID, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: %w", method, err)
	}

	return user, nil
}

func (u *User) GetUserData(ctx context.Context, appID, userID string) (entity.User, error) {
	const method = "service.user.GetUserData"

	user, err := u.storage.GetUserData(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: %w", method, err)
	}

	return user, nil
}

func (u *User) UpdateUser(ctx context.Context, user entity.User) error {
	const method = "service.user.UpdateUser"

	if err := u.storage.UpdateUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (u *User) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	const method = "service.user.GetUserStatusByEmail"

	status, err := u.storage.GetUserStatusByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return status, nil
}

func (u *User) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	const method = "service.user.GetUserStatusByID"

	status, err := u.storage.GetUserStatusByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return status, nil
}

func (u *User) DeleteUser(ctx context.Context, user entity.User) error {
	const method = "service.user.DeleteUser"

	if err := u.storage.DeleteUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (u *User) DeleteUserTokens(ctx context.Context, appID, userID string) error {
	const method = "service.user.DeleteUserTokens"

	if err := u.storage.DeleteAllTokens(ctx, appID, userID); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}
