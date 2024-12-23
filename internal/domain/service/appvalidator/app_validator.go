package appvalidator

import (
	"context"
	"errors"
	"fmt"
	"github.com/rshelekhov/sso/src/domain"
	"github.com/rshelekhov/sso/src/infrastructure/storage"
)

type AppValidator struct {
	storage Storage
}

type Validator interface {
	ValidateAppID(ctx context.Context, appID string) error
}

//go:generate go run github.com/vektra/mockery/v2@v2.20.2 --name=Storage --filename=mock_app_storage.go
type Storage interface {
	CheckAppIDExists(ctx context.Context, appID string) error
}

func NewService(storage Storage) *AppValidator {
	return &AppValidator{
		storage: storage,
	}
}

func (s *AppValidator) ValidateAppID(ctx context.Context, appID string) error {
	const method = "service.appvalidator.ValidateAppID"

	if err := s.storage.CheckAppIDExists(ctx, appID); err != nil {
		if errors.Is(err, storage.ErrAppIDDoesNotExist) {
			return domain.ErrAppNotFound
		}

		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}
