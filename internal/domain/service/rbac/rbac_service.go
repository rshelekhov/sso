package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type Storage interface {
	GetUserRole(ctx context.Context, appID, userID string) (string, error)
	SetUserRole(ctx context.Context, appID, userID, role string) error
}

type Service struct {
	storage Storage
}

func NewService(storage Storage) *Service {
	return &Service{
		storage: storage,
	}
}

func (s *Service) GetUserRole(ctx context.Context, appID, userID string) (Role, error) {
	const method = "rbac.GetUserRole"

	role, err := s.storage.GetUserRole(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return "", domain.ErrUserNotFound
		}
		return "", fmt.Errorf("%s: failed to get user role: %w", method, err)
	}

	return Role(role), nil
}

func (s *Service) SetUserRole(ctx context.Context, appID, userID string, role Role) error {
	const method = "rbac.SetUserRole"

	if !IsValidRole(role) {
		return fmt.Errorf("%s: invalid role: %s", method, role)
	}

	err := s.storage.SetUserRole(ctx, appID, userID, role.String())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("%s: failed to set user role in database: %w", method, err)
	}

	return nil
}
