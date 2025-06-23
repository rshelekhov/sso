package userdata

import (
	"context"
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type UserData struct {
	storage Storage
}

type Storage interface {
	GetUserByID(ctx context.Context, userID string) (entity.User, error)
	GetUserByEmail(ctx context.Context, email string) (entity.User, error)
	GetUserData(ctx context.Context, userID string) (entity.User, error)
	UpdateUser(ctx context.Context, user entity.User) error
	GetUserStatusByEmail(ctx context.Context, email string) (string, error)
	GetUserStatusByID(ctx context.Context, userID string) (string, error)
	DeleteUser(ctx context.Context, user entity.User) error
}

func NewService(storage Storage) *UserData {
	return &UserData{
		storage: storage,
	}
}

func (d *UserData) GetUserByID(ctx context.Context, userID string) (entity.User, error) {
	const method = "service.user.GetUserByID"

	user, err := d.storage.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: %w", method, err)
	}

	return user, nil
}

func (d *UserData) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	const method = "service.user.GetUserByEmail"

	user, err := d.storage.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: %w", method, err)
	}

	return user, nil
}

func (d *UserData) GetUserData(ctx context.Context, userID string) (entity.User, error) {
	const method = "service.user.GetUserData"

	user, err := d.storage.GetUserData(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, fmt.Errorf("%s: %w", method, err)
	}

	return user, nil
}

func (d *UserData) UpdateUserData(ctx context.Context, user entity.User) error {
	const method = "service.user.UpdateUser"

	if err := d.storage.UpdateUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}

func (d *UserData) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	const method = "service.user.GetUserStatusByEmail"

	status, err := d.storage.GetUserStatusByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return status, nil
}

func (d *UserData) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	const method = "service.user.GetUserStatusByID"

	status, err := d.storage.GetUserStatusByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return status, nil
}

func (d *UserData) DeleteUser(ctx context.Context, user entity.User) error {
	const method = "service.user.DeleteUser"

	if err := d.storage.DeleteUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}
