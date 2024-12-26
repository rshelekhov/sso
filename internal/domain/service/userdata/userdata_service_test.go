package userdata

import (
	"context"
	"errors"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/userdata/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestGetUserByID(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	t.Run("Success", func(t *testing.T) {
		expectedUser := entity.User{
			Email:     "test-email@gmail.com",
			AppID:     appID,
			Verified:  true,
			UpdatedAt: time.Now(),
		}

		mockUserStorage.
			On("GetUserByID", ctx, appID, userID).
			Once().
			Return(expectedUser, nil)

		user, err := userService.GetUserByID(ctx, appID, userID)
		require.NoError(t, err)
		require.Equal(t, expectedUser, user)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("GetUserByID", ctx, appID, userID).
			Once().
			Return(entity.User{}, storage.ErrUserNotFound)

		user, err := userService.GetUserByID(ctx, appID, userID)
		require.Empty(t, user)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("GetUserByID", ctx, appID, userID).
			Once().
			Return(entity.User{}, errors.New("storage error"))

		user, err := userService.GetUserByID(ctx, appID, userID)
		require.Empty(t, user)
		require.Error(t, err)
	})
}

func TestGetUserByEmail(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	appID := "test-app-id"
	email := "test-email@gmail.com"

	t.Run("Success", func(t *testing.T) {
		expectedUser := entity.User{
			Email:     "test-email@gmail.com",
			AppID:     appID,
			Verified:  true,
			UpdatedAt: time.Now(),
		}

		mockUserStorage.
			On("GetUserByEmail", ctx, appID, email).
			Once().
			Return(expectedUser, nil)

		user, err := userService.GetUserByEmail(ctx, appID, email)
		require.NoError(t, err)
		require.Equal(t, expectedUser, user)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("GetUserByEmail", ctx, appID, email).
			Once().
			Return(entity.User{}, storage.ErrUserNotFound)

		user, err := userService.GetUserByEmail(ctx, appID, email)
		require.Empty(t, user)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("GetUserByEmail", ctx, appID, email).
			Once().
			Return(entity.User{}, errors.New("storage error"))

		user, err := userService.GetUserByEmail(ctx, appID, email)
		require.Empty(t, user)
		require.Error(t, err)
	})
}

func TestGetUserData(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	t.Run("Success", func(t *testing.T) {
		mockUserStorage.
			On("GetUserData", ctx, appID, userID).
			Once().
			Return(entity.User{
				ID:        userID,
				Email:     "test-email@gmail.com",
				AppID:     appID,
				Verified:  true,
				UpdatedAt: time.Now(),
			}, nil)

		user, err := userService.GetUserData(ctx, appID, userID)
		require.NotEmpty(t, user)
		require.NoError(t, err)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("GetUserData", ctx, appID, userID).
			Once().
			Return(entity.User{}, storage.ErrUserNotFound)

		user, err := userService.GetUserData(ctx, appID, userID)
		require.Empty(t, user)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("GetUserData", ctx, appID, userID).
			Once().
			Return(entity.User{}, errors.New("storage error"))

		user, err := userService.GetUserData(ctx, appID, userID)
		require.Empty(t, user)
		require.Error(t, err)
	})
}

func TestUpdateUser(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	updatedUserData := entity.User{
		ID:           "test-user-id",
		Email:        "test-email@gmail.com",
		PasswordHash: "password-hash",
		AppID:        "test-app-id",
	}

	t.Run("Success", func(t *testing.T) {
		mockUserStorage.
			On("UpdateUser", ctx, updatedUserData).
			Once().
			Return(nil)

		err := userService.UpdateUser(ctx, updatedUserData)
		require.NoError(t, err)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("UpdateUser", ctx, updatedUserData).
			Once().
			Return(storage.ErrUserNotFound)

		err := userService.UpdateUser(ctx, updatedUserData)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("UpdateUser", ctx, updatedUserData).
			Once().
			Return(errors.New("storage error"))

		err := userService.UpdateUser(ctx, updatedUserData)
		require.Error(t, err)
	})
}

func TestGetUserStatusByEmail(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	email := "test-email@gmail.com"

	t.Run("Success", func(t *testing.T) {
		mockUserStorage.
			On("GetUserStatusByEmail", ctx, email).
			Once().
			Return("active", nil)

		status, err := userService.GetUserStatusByEmail(ctx, email)
		require.NotEmpty(t, status)
		require.NoError(t, err)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("GetUserStatusByEmail", ctx, email).
			Once().
			Return("", storage.ErrUserNotFound)

		status, err := userService.GetUserStatusByEmail(ctx, email)
		require.Empty(t, status)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("GetUserStatusByEmail", ctx, email).
			Once().
			Return("", errors.New("storage error"))

		status, err := userService.GetUserStatusByEmail(ctx, email)
		require.Empty(t, status)
		require.Error(t, err)
	})
}

func TestGetUserStatusByID(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	userID := "test-user-id"

	t.Run("Success", func(t *testing.T) {
		mockUserStorage.
			On("GetUserStatusByID", ctx, userID).
			Once().
			Return("active", nil)

		status, err := userService.GetUserStatusByID(ctx, userID)
		require.NotEmpty(t, status)
		require.NoError(t, err)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("GetUserStatusByID", ctx, userID).
			Once().
			Return("", storage.ErrUserNotFound)

		status, err := userService.GetUserStatusByID(ctx, userID)
		require.Empty(t, status)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("GetUserStatusByID", ctx, userID).
			Once().
			Return("", errors.New("storage error"))

		status, err := userService.GetUserStatusByID(ctx, userID)
		require.Empty(t, status)
		require.Error(t, err)
	})
}

func TestDeleteUser(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	deletedUser := entity.User{
		ID:        "test-user-id",
		AppID:     "test-app-id",
		DeletedAt: time.Now(),
	}

	t.Run("Success", func(t *testing.T) {
		mockUserStorage.
			On("DeleteUser", ctx, deletedUser).
			Once().
			Return(nil)

		err := userService.DeleteUser(ctx, deletedUser)
		require.NoError(t, err)
	})

	t.Run("Error – UserData not found", func(t *testing.T) {
		mockUserStorage.
			On("DeleteUser", ctx, deletedUser).
			Once().
			Return(storage.ErrUserNotFound)

		err := userService.DeleteUser(ctx, deletedUser)
		require.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("DeleteUser", ctx, deletedUser).
			Once().
			Return(errors.New("storage error"))

		err := userService.DeleteUser(ctx, deletedUser)
		require.Error(t, err)
	})
}

func TestDeleteUserTokens(t *testing.T) {
	mockUserStorage := new(mocks.Storage)

	userService := NewService(mockUserStorage)

	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	t.Run("Success", func(t *testing.T) {
		mockUserStorage.
			On("DeleteAllTokens", ctx, appID, userID).
			Once().
			Return(nil)

		err := userService.DeleteUserTokens(ctx, appID, userID)
		require.NoError(t, err)
	})

	t.Run("Error – Storage error", func(t *testing.T) {
		mockUserStorage.
			On("DeleteAllTokens", ctx, appID, userID).
			Once().
			Return(errors.New("storage error"))

		err := userService.DeleteUserTokens(ctx, appID, userID)
		require.Error(t, err)
	})
}
