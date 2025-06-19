package clientvalidator

import (
	"context"
	"errors"
	"fmt"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
)

type ClientValidator struct {
	storage Storage
}

type Validator interface {
	ValidateClientID(ctx context.Context, clientID string) error
}

type Storage interface {
	CheckClientIDExists(ctx context.Context, clientID string) error
}

func NewService(storage Storage) *ClientValidator {
	return &ClientValidator{
		storage: storage,
	}
}

func (s *ClientValidator) ValidateClientID(ctx context.Context, clientID string) error {
	const method = "service.clientvalidator.ValidateClientID"

	if err := s.storage.CheckClientIDExists(ctx, clientID); err != nil {
		if errors.Is(err, storage.ErrClientIDDoesNotExist) {
			return domain.ErrClientNotFound
		}

		return fmt.Errorf("%s: %w", method, err)
	}

	return nil
}
