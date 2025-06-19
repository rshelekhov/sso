package clientvalidator

import (
	"context"
	"errors"
	"testing"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/require"
)

func TestValidateClientID(t *testing.T) {
	mockClientStorage := new(mocks.Storage)

	clientValidator := NewService(mockClientStorage)

	ctx := context.Background()
	clientID := "test-app-id"

	t.Run("Success", func(t *testing.T) {
		mockClientStorage.
			On("CheckClientIDExists", ctx, clientID).
			Once().
			Return(nil)

		err := clientValidator.ValidateClientID(ctx, clientID)
		require.NoError(t, err)
	})

	t.Run("Error – App not found", func(t *testing.T) {
		mockClientStorage.
			On("CheckClientIDExists", ctx, clientID).
			Once().
			Return(storage.ErrClientIDDoesNotExist)

		err := clientValidator.ValidateClientID(ctx, clientID)
		require.ErrorIs(t, err, domain.ErrClientNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockClientStorage.
			On("CheckClientIDExists", ctx, clientID).
			Once().
			Return(errors.New("storage error"))

		err := clientValidator.ValidateClientID(ctx, clientID)
		require.Error(t, err)
	})
}
