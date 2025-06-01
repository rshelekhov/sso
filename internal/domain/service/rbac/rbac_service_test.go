package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/rshelekhov/sso/internal/domain/service/rbac/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRBACService_GetUserRole(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"
	expectedRole := Role("admin")

	tests := []struct {
		name          string
		appID         string
		userID        string
		mockBehavior  func(storage *mocks.Storage)
		expectedRole  Role
		expectedError error
	}{
		{
			name:   "Success",
			appID:  appID,
			userID: userID,
			mockBehavior: func(storage *mocks.Storage) {
				storage.EXPECT().GetUserRole(ctx, appID, userID).
					Once().
					Return(expectedRole.String(), nil)
			},
			expectedRole:  expectedRole,
			expectedError: nil,
		},
		{
			name:   "Failed to get role",
			appID:  appID,
			userID: userID,
			mockBehavior: func(storage *mocks.Storage) {
				storage.EXPECT().GetUserRole(ctx, appID, userID).
					Once().
					Return("", errors.New("database error"))
			},
			expectedRole:  "",
			expectedError: errors.New("rbac.GetUserRole: failed to get user role: database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := mocks.NewStorage(t)

			tt.mockBehavior(storage)

			service := NewService(storage)

			role, err := service.GetUserRole(ctx, tt.appID, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedRole, role)
			}
		})
	}
}

func TestRBACService_SetUserRole(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"
	role := Role("admin")

	tests := []struct {
		name          string
		appID         string
		userID        string
		role          Role
		mockBehavior  func(storage *mocks.Storage)
		expectedError error
	}{
		{
			name:   "Success",
			appID:  appID,
			userID: userID,
			role:   role,
			mockBehavior: func(storage *mocks.Storage) {
				storage.EXPECT().SetUserRole(ctx, appID, userID, role.String()).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "Invalid role",
			appID:  appID,
			userID: userID,
			role:   Role("invalid"),
			mockBehavior: func(storage *mocks.Storage) {
				// No mocks needed for invalid role case
			},
			expectedError: errors.New("rbac.SetUserRole: invalid role: invalid"),
		},
		{
			name:   "Failed to set role",
			appID:  appID,
			userID: userID,
			role:   role,
			mockBehavior: func(storage *mocks.Storage) {
				storage.EXPECT().SetUserRole(ctx, appID, userID, role.String()).
					Once().
					Return(errors.New("database error"))
			},
			expectedError: errors.New("rbac.SetUserRole: failed to set user role in database: database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := mocks.NewStorage(t)

			tt.mockBehavior(storage)

			service := NewService(storage)

			err := service.SetUserRole(ctx, tt.appID, tt.userID, tt.role)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
