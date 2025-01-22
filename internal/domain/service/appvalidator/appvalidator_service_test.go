package appvalidator

import (
	"context"
	"errors"
	"testing"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/appvalidator/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/require"
)

func TestValidateAppID(t *testing.T) {
	mockAppStorage := new(mocks.Storage)

	appValidator := NewService(mockAppStorage)

	ctx := context.Background()
	appID := "test-app-id"

	t.Run("Success", func(t *testing.T) {
		mockAppStorage.
			On("CheckAppIDExists", ctx, appID).
			Once().
			Return(nil)

		err := appValidator.ValidateAppID(ctx, appID)
		require.NoError(t, err)
	})

	t.Run("Error – App not found", func(t *testing.T) {
		mockAppStorage.
			On("CheckAppIDExists", ctx, appID).
			Once().
			Return(storage.ErrAppIDDoesNotExist)

		err := appValidator.ValidateAppID(ctx, appID)
		require.ErrorIs(t, err, domain.ErrAppNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockAppStorage.
			On("CheckAppIDExists", ctx, appID).
			Once().
			Return(errors.New("storage error"))

		err := appValidator.ValidateAppID(ctx, appID)
		require.Error(t, err)
	})
}
