package appvalidator

import (
	"context"
	"errors"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type Storage interface {
	CheckAppIDExists(ctx context.Context, appID string) error
}

type AppValidator struct {
	storage Storage
}

func NewService(storage Storage) *AppValidator {
	return &AppValidator{
		storage: storage,
	}
}

var (
	ErrAppIDDoesNotExist = errors.New("app ID does not exist")
)

func (s *AppValidator) ValidateAppID(ctx context.Context, appID string) error {
	if err := s.storage.CheckAppIDExists(ctx, appID); err != nil {
		if errors.Is(err, storage.ErrAppIDDoesNotExist) {
			return ErrAppIDDoesNotExist
		}

		return err
	}

	return nil
}
