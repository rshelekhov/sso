package userdata

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/userdata/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/require"
)

func TestUserDataService_GetUserByID(t *testing.T) {
	clientID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name          string
		mockBehavior  func(userStorage *mocks.Storage)
		expectedUser  entity.User
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(userStorage *mocks.Storage) {
				expectedUser := entity.User{
					Email:     "test-email@gmail.com",
					ClientID:  clientID,
					Verified:  true,
					UpdatedAt: time.Now(),
				}
				userStorage.EXPECT().
					GetUserByID(context.Background(), clientID, userID).
					Return(expectedUser, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - User not found",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserByID(context.Background(), clientID, userID).
					Return(entity.User{}, storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error - Storage error",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserByID(context.Background(), clientID, "test-user-id").
					Return(entity.User{}, errors.New("storage error"))
			},
			expectedError: errors.New("storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)
			user, err := service.GetUserByID(context.Background(), clientID, userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
				require.Empty(t, user)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, user)
			}
		})
	}
}

func TestUserDataService_GetUserByEmail(t *testing.T) {
	clientID := "test-app-id"
	email := "test-email@gmail.com"

	tests := []struct {
		name          string
		mockBehavior  func(userStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(userStorage *mocks.Storage) {
				expectedUser := entity.User{
					Email:     email,
					ClientID:  clientID,
					Verified:  true,
					UpdatedAt: time.Now(),
				}
				userStorage.EXPECT().
					GetUserByEmail(context.Background(), clientID, email).
					Return(expectedUser, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - User not found",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserByEmail(context.Background(), clientID, email).
					Return(entity.User{}, storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error - Storage error",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserByEmail(context.Background(), clientID, email).
					Return(entity.User{}, errors.New("user storage error"))
			},
			expectedError: errors.New("user storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)
			user, err := service.GetUserByEmail(context.Background(), clientID, email)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
				require.Empty(t, user)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, user)
			}
		})
	}
}

func TestUserDataService_GetUserData(t *testing.T) {
	ctx := context.Background()
	clientID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name          string
		mockBehavior  func(userStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().GetUserData(ctx, clientID, userID).
					Once().
					Return(entity.User{
						ID:        userID,
						Email:     "test-email@gmail.com",
						ClientID:  clientID,
						Verified:  true,
						UpdatedAt: time.Now(),
					}, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error – User not found",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().GetUserData(ctx, clientID, userID).
					Once().
					Return(entity.User{}, storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error – Storage error",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().GetUserData(ctx, clientID, userID).
					Once().
					Return(entity.User{}, fmt.Errorf("user storage error"))
			},
			expectedError: fmt.Errorf("user storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)

			user, err := service.GetUserData(ctx, clientID, userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
				require.Empty(t, user)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, user)
			}
		})
	}
}

func TestUserDataService_UpdateUser(t *testing.T) {
	updatedUser := entity.User{
		ID:           "test-user-id",
		Email:        "test-email@gmail.com",
		PasswordHash: "password-hash",
		ClientID:     "test-client-id",
	}

	tests := []struct {
		name          string
		user          entity.User
		mockBehavior  func(userStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			user: updatedUser,
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					UpdateUser(context.Background(), updatedUser).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - User not found",
			user: updatedUser,
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					UpdateUser(context.Background(), updatedUser).
					Return(storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error - Storage error",
			user: updatedUser,
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					UpdateUser(context.Background(), updatedUser).
					Return(errors.New("user storage error"))
			},
			expectedError: errors.New("user storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)
			err := service.UpdateUserData(context.Background(), tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserDataService_GetUserStatusByEmail(t *testing.T) {
	ctx := context.Background()
	clientID := "test-app-id"
	email := "email@example.com"

	tests := []struct {
		name          string
		mockBehavior  func(userStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserStatusByEmail(ctx, clientID, email).
					Return("active", nil)
			},
			expectedError: nil,
		},
		{
			name: "Error — User not found",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserStatusByEmail(ctx, clientID, email).
					Return("", storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error - Storage error",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserStatusByEmail(ctx, clientID, email).
					Return("", errors.New("user storage error"))
			},
			expectedError: errors.New("user storage error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)

			var status string
			var err error

			status, err = service.GetUserStatusByEmail(ctx, clientID, email)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
				require.Empty(t, status)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, status)
			}
		})
	}
}

func TestUserDataService_GetUserStatusByID(t *testing.T) {
	ctx := context.Background()
	clientID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name          string
		mockBehavior  func(userStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserStatusByID(ctx, clientID, userID).
					Return("active", nil)
			},
			expectedError: nil,
		},
		{
			name: "Error — User not found",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserStatusByID(ctx, clientID, userID).
					Return("", storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error - Storage error",
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					GetUserStatusByID(ctx, clientID, userID).
					Return("", errors.New("user storage error"))
			},
			expectedError: errors.New("user storage error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)

			var status string
			var err error

			status, err = service.GetUserStatusByID(ctx, clientID, userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
				require.Empty(t, status)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, status)
			}
		})
	}
}

func TestUserDataService_DeleteUser(t *testing.T) {
	deletedUser := entity.User{
		ID:        "test-user-id",
		ClientID:  "test-client-id",
		DeletedAt: time.Now(),
	}

	tests := []struct {
		name          string
		user          entity.User
		mockBehavior  func(userStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			user: deletedUser,
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					DeleteUser(context.Background(), deletedUser).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - User not found",
			user: deletedUser,
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					DeleteUser(context.Background(), deletedUser).
					Return(storage.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Error - Storage error",
			user: deletedUser,
			mockBehavior: func(userStorage *mocks.Storage) {
				userStorage.EXPECT().
					DeleteUser(context.Background(), deletedUser).
					Return(errors.New("user storage error"))
			},
			expectedError: errors.New("user storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := mocks.NewStorage(t)
			tt.mockBehavior(mockStorage)

			service := NewService(mockStorage)
			err := service.DeleteUser(context.Background(), tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
