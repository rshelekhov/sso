package user

import (
	"context"
	"errors"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type Service interface {
	GetUserByID(ctx context.Context, userID, appID string) (entity.User, error)
	GetUserByEmail(ctx context.Context, email, appID string) (entity.User, error)
	GetUserData(ctx context.Context, userID, appID string) (entity.User, error)
	UpdateUser(ctx context.Context, user entity.User) error
	GetUserStatusByEmail(ctx context.Context, email string) (string, error)
	GetUserStatusByID(ctx context.Context, userID string) (string, error)
	DeleteUser(ctx context.Context, user entity.User) error
	DeleteUserTokens(ctx context.Context, userID, appID string) error
}

type Storage interface {
	GetUserByID(ctx context.Context, userID, appID string) (entity.User, error)
	GetUserByEmail(ctx context.Context, email, appID string) (entity.User, error)
	GetUserData(ctx context.Context, userID, appID string) (entity.User, error)
	UpdateUser(ctx context.Context, user entity.User) error
	GetUserStatusByEmail(ctx context.Context, email string) (string, error)
	GetUserStatusByID(ctx context.Context, userID string) (string, error)
	DeleteUser(ctx context.Context, user entity.User) error
	DeleteAllTokens(ctx context.Context, userID, appID string) error
}

type User struct {
	storage Storage
}

func NewService(storage Storage) *User {
	return &User{
		storage: storage,
	}
}

func (u *User) GetUserByID(ctx context.Context, userID, appID string) (entity.User, error) {
	user, err := u.storage.GetUserByID(ctx, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, err
	}

	return user, nil
}

func (u *User) GetUserByEmail(ctx context.Context, email, appID string) (entity.User, error) {
	user, err := u.storage.GetUserByEmail(ctx, email, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, err
	}

	return user, nil
}

func (u *User) GetUserData(ctx context.Context, userID, appID string) (entity.User, error) {
	user, err := u.storage.GetUserData(ctx, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return entity.User{}, domain.ErrUserNotFound
		}
		return entity.User{}, err
	}

	return user, nil
}

func (u *User) UpdateUser(ctx context.Context, user entity.User) error {
	return u.storage.UpdateUser(ctx, user)
}

func (u *User) GetUserStatusByEmail(ctx context.Context, email string) (string, error) {
	status, err := u.storage.GetUserStatusByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", err
	}

	return status, nil
}

func (u *User) GetUserStatusByID(ctx context.Context, userID string) (string, error) {
	status, err := u.storage.GetUserStatusByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", err
	}

	return status, nil
}

func (u *User) DeleteUser(ctx context.Context, user entity.User) error {
	if err := u.storage.DeleteUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return err
	}

	return nil
}

func (u *User) DeleteUserTokens(ctx context.Context, userID, appID string) error {
	return u.storage.DeleteAllTokens(ctx, userID, appID)
}
