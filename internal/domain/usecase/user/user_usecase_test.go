package user

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/rbac"
	"github.com/rshelekhov/sso/internal/domain/usecase/user/mocks"
	"github.com/rshelekhov/sso/internal/lib/logger/handler/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUserUsecase_GetUser(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	expectedUser := entity.User{
		ID:        userID,
		Email:     "test@example.com",
		AppID:     appID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tests := []struct {
		name          string
		mockBehavior  func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager)
		expectedError error
		expectedUser  entity.User
	}{
		{
			name: "Success",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserByID(ctx, appID, userID).
					Once().
					Return(expectedUser, nil)
			},
			expectedError: nil,
			expectedUser:  expectedUser,
		},
		{
			name: "Failed to extract user ID",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return("", domain.ErrFailedToExtractUserIDFromContext)
			},
			expectedError: domain.ErrFailedToExtractUserIDFromContext,
			expectedUser:  entity.User{},
		},
		{
			name: "User not found",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserByID(ctx, appID, userID).
					Once().
					Return(entity.User{}, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
			expectedUser:  entity.User{},
		},
		{
			name: "Failed to get user",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserByID(ctx, appID, userID).
					Once().
					Return(entity.User{}, fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToGetUserByID,
			expectedUser:  entity.User{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identityMgr := mocks.NewIdentityManager(t)
			userMgr := mocks.NewUserdataManager(t)

			tt.mockBehavior(identityMgr, userMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, nil, nil, userMgr, nil, identityMgr, nil, nil)

			userData, err := user.GetUser(ctx, appID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, userData)
			}
		})
	}
}

func TestUserUsecase_GetUserByID(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	expectedUser := entity.User{
		ID:        userID,
		Email:     "test@example.com",
		AppID:     appID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tests := []struct {
		name          string
		mockBehavior  func(iuserMgr *mocks.UserdataManager)
		expectedError error
		expectedUser  entity.User
	}{
		{
			name: "Success",
			mockBehavior: func(userMgr *mocks.UserdataManager) {
				userMgr.EXPECT().GetUserByID(ctx, appID, userID).
					Once().
					Return(expectedUser, nil)
			},
			expectedError: nil,
			expectedUser:  expectedUser,
		},
		{
			name: "User not found",
			mockBehavior: func(userMgr *mocks.UserdataManager) {
				userMgr.EXPECT().GetUserByID(ctx, appID, userID).
					Once().
					Return(entity.User{}, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
			expectedUser:  entity.User{},
		},
		{
			name: "Failed to get user",
			mockBehavior: func(userMgr *mocks.UserdataManager) {
				userMgr.EXPECT().GetUserByID(ctx, appID, userID).
					Once().
					Return(entity.User{}, fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToGetUserByID,
			expectedUser:  entity.User{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)

			tt.mockBehavior(userMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, nil, nil, userMgr, nil, nil, nil, nil)

			userData, err := user.GetUserByID(ctx, appID, userID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, userData)
			}
		})
	}
}

func TestUserUsecase_UpdateUser(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"
	currentEmail := "old@example.com"
	newEmail := "new@example.com"
	currentPassword := "old-password"
	newPassword := "new-password"
	currentPasswordHash := "old-password-hash"
	newPasswordHash := "new-password-hash"

	existingUser := entity.User{
		ID:           userID,
		Email:        currentEmail,
		PasswordHash: currentPasswordHash,
		AppID:        appID,
	}

	tests := []struct {
		name         string
		reqData      entity.UserRequestData
		mockBehavior func(
			identityMgr *mocks.IdentityManager,
			userMgr *mocks.UserdataManager,
			passwordMgr *mocks.PasswordManager,
		)
		expectedError error
	}{
		{
			name: "Success - Update email only",
			reqData: entity.UserRequestData{
				Email: newEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				userMgr.EXPECT().GetUserStatusByEmail(ctx, appID, newEmail).
					Once().
					Return(entity.UserStatusNotFound.String(), nil)

				userMgr.EXPECT().UpdateUserData(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Success - Update password only",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(true, nil)

				// Check if the new password does not match the current password
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, newPassword).
					Once().
					Return(false, nil)

				passwordMgr.EXPECT().HashPassword(newPassword).
					Once().
					Return(newPasswordHash, nil)

				userMgr.EXPECT().UpdateUserData(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to extract user ID",
			reqData: entity.UserRequestData{
				Email: newEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return("", domain.ErrFailedToExtractUserIDFromContext)
			},
			expectedError: domain.ErrFailedToExtractUserIDFromContext,
		},
		{
			name: "User not found",
			reqData: entity.UserRequestData{
				Email: newEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{}, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Failed to get user",
			reqData: entity.UserRequestData{
				Email: newEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(entity.User{}, fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToGetUserData,
		},
		{
			name: "Email already taken",
			reqData: entity.UserRequestData{
				Email: newEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				userMgr.EXPECT().GetUserStatusByEmail(ctx, appID, newEmail).
					Once().
					Return(entity.UserStatusActive.String(), nil)
			},
			expectedError: domain.ErrEmailAlreadyTaken,
		},
		{
			name: "Update email — No email changes detected",
			reqData: entity.UserRequestData{
				Email: currentEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)
			},
			expectedError: domain.ErrNoEmailChangesDetected,
		},
		{
			name: "Update email — Failed to get user status by email",
			reqData: entity.UserRequestData{
				Email: newEmail,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				userMgr.EXPECT().GetUserStatusByEmail(ctx, appID, newEmail).
					Once().
					Return("", fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToGetUserStatusByEmail,
		},
		{
			name: "Update password – Failed to validate current password",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(false, fmt.Errorf("password manager error"))
			},
			expectedError: domain.ErrFailedToCheckPasswordHashMatch,
		},

		{
			name: "Update password - current password does not match",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(false, nil)
			},
			expectedError: domain.ErrPasswordsDoNotMatch,
		},

		{
			name: "Update password - Failed to validate new password",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(true, nil)

				// Check if the new password does not match the current password
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, newPassword).
					Once().
					Return(false, fmt.Errorf("password manager error"))
			},
			expectedError: domain.ErrFailedToCheckPasswordHashMatch,
		},
		{
			name: "Update password - New password is the same as the current password",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(true, nil)

				// Check if the new password does not match the current password
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, newPassword).
					Once().
					Return(true, nil)
			},
			expectedError: domain.ErrNoPasswordChangesDetected,
		},
		{
			name: "Update password — Failed to hash new password",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(true, nil)

				// Check if the new password does not match the current password
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, newPassword).
					Once().
					Return(false, nil)

				passwordMgr.EXPECT().HashPassword(newPassword).
					Once().
					Return("", fmt.Errorf("password manager error"))
			},
			expectedError: domain.ErrFailedToGeneratePasswordHash,
		},
		{
			name: "Failed to update user data",
			reqData: entity.UserRequestData{
				Password:        currentPassword,
				UpdatedPassword: newPassword,
			},
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				passwordMgr *mocks.PasswordManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, appID, userID).
					Once().
					Return(existingUser, nil)

				// Check if the current password is correct
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, currentPassword).
					Once().
					Return(true, nil)

				// Check if the new password does not match the current password
				passwordMgr.EXPECT().PasswordMatch(existingUser.PasswordHash, newPassword).
					Once().
					Return(false, nil)

				passwordMgr.EXPECT().HashPassword(newPassword).
					Once().
					Return(newPasswordHash, nil)

				userMgr.EXPECT().UpdateUserData(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToUpdateUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identityMgr := mocks.NewIdentityManager(t)
			userMgr := mocks.NewUserdataManager(t)
			passwordMgr := mocks.NewPasswordManager(t)

			tt.mockBehavior(identityMgr, userMgr, passwordMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, nil, nil, userMgr, passwordMgr, identityMgr, nil, nil)

			updatedUser, err := user.UpdateUser(ctx, appID, tt.reqData)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.reqData.Email, updatedUser.Email)
			}
		})
	}
}

func TestUserUsecase_DeleteUser(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name         string
		mockBehavior func(
			identityMgr *mocks.IdentityManager,
			userMgr *mocks.UserdataManager,
			sessionMgr *mocks.SessionManager,
			verificationMgr *mocks.VerificationManager,
			txMgr *mocks.TransactionManager,
		)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserDevices(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				verificationMgr.EXPECT().DeleteAllTokens(ctx, appID, userID).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to extract user ID",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return("", domain.ErrFailedToExtractUserIDFromContext)
			},
			expectedError: domain.ErrFailedToExtractUserIDFromContext,
		},
		{
			name: "User not found",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusSoftDeleted.String(), nil)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Unknown user status",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return("some-unknown-user-status", nil)
			},
			expectedError: domain.ErrUnknownUserStatus,
		},
		{
			name: "Failed to check if user exists",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return("", fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToGetUserStatusByID,
		},
		{
			name: "Failed to delete user data",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToDeleteUser,
		},
		{
			name: "Failed to delete user sessions",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("session manager error"))
			},
			expectedError: domain.ErrFailedToDeleteAllUserSessions,
		},
		{
			name: "Failed to delete user devices",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserDevices(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToDeleteUserDevices,
		},
		{
			name: "Failed to delete user tokens",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserDevices(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				verificationMgr.EXPECT().DeleteAllTokens(ctx, appID, userID).
					Once().
					Return(fmt.Errorf("verification manager error"))
			},
			expectedError: domain.ErrFailedToDeleteUserTokens,
		},
		{
			name: "Failed to commit transaction",
			mockBehavior: func(
				identityMgr *mocks.IdentityManager,
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, appID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fmt.Errorf("some error")
					})
			},
			expectedError: fmt.Errorf("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identityMgr := mocks.NewIdentityManager(t)
			userMgr := mocks.NewUserdataManager(t)
			sessionMgr := mocks.NewSessionManager(t)
			verificationMgr := mocks.NewVerificationManager(t)
			txMgr := mocks.NewTransactionManager(t)

			tt.mockBehavior(identityMgr, userMgr, sessionMgr, verificationMgr, txMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, nil, sessionMgr, userMgr, nil, identityMgr, verificationMgr, txMgr)

			err := user.DeleteUser(ctx, appID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserUsecase_DeleteUserByID(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name         string
		mockBehavior func(
			userMgr *mocks.UserdataManager,
			sessionMgr *mocks.SessionManager,
			verificationMgr *mocks.VerificationManager,
			txMgr *mocks.TransactionManager,
		)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserDevices(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				verificationMgr.EXPECT().DeleteAllTokens(ctx, appID, userID).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "User not found",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusSoftDeleted.String(), nil)
			},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "Unknown user status",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return("some-unknown-user-status", nil)
			},
			expectedError: domain.ErrUnknownUserStatus,
		},
		{
			name: "Failed to check if user exists",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return("", fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToGetUserStatusByID,
		},
		{
			name: "Failed to delete user data",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToDeleteUser,
		},
		{
			name: "Failed to delete user sessions",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("session manager error"))
			},
			expectedError: domain.ErrFailedToDeleteAllUserSessions,
		},
		{
			name: "Failed to delete user devices",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserDevices(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(fmt.Errorf("user manager error"))
			},
			expectedError: domain.ErrFailedToDeleteUserDevices,
		},
		{
			name: "Failed to delete user tokens",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, appID, userID).
					Once().
					Return(entity.UserStatusActive.String(), nil)

				userMgr.EXPECT().DeleteUser(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserSessions(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				sessionMgr.EXPECT().DeleteUserDevices(ctx, mock.AnythingOfType("entity.User")).
					Once().
					Return(nil)

				verificationMgr.EXPECT().DeleteAllTokens(ctx, appID, userID).
					Once().
					Return(fmt.Errorf("verification manager error"))
			},
			expectedError: domain.ErrFailedToDeleteUserTokens,
		},
		{
			name: "Failed to commit transaction",
			mockBehavior: func(
				userMgr *mocks.UserdataManager,
				sessionMgr *mocks.SessionManager,
				verificationMgr *mocks.VerificationManager,
				txMgr *mocks.TransactionManager,
			) {
				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fmt.Errorf("some error")
					})
			},
			expectedError: fmt.Errorf("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userMgr := mocks.NewUserdataManager(t)
			sessionMgr := mocks.NewSessionManager(t)
			verificationMgr := mocks.NewVerificationManager(t)
			txMgr := mocks.NewTransactionManager(t)

			tt.mockBehavior(userMgr, sessionMgr, verificationMgr, txMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, nil, sessionMgr, userMgr, nil, nil, verificationMgr, txMgr)

			err := user.DeleteUserByID(ctx, appID, userID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserUsecase_GetUserRole(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name          string
		mockBehavior  func(rbacMgr *mocks.RBACManager)
		expectedError error
		expectedRole  string
	}{
		{
			name: "Success",
			mockBehavior: func(rbacMgr *mocks.RBACManager) {
				rbacMgr.EXPECT().GetUserRole(ctx, appID, userID).
					Once().
					Return(rbac.Role("admin"), nil)
			},
			expectedError: nil,
			expectedRole:  "admin",
		},
		{
			name: "Failed to get user role",
			mockBehavior: func(rbacMgr *mocks.RBACManager) {
				rbacMgr.EXPECT().GetUserRole(ctx, appID, userID).
					Once().
					Return(rbac.Role(""), fmt.Errorf("rbac manager error"))
			},
			expectedError: domain.ErrFailedToGetUserRole,
			expectedRole:  "",
		},
		{
			name: "Role received but cache update failed",
			mockBehavior: func(rbacMgr *mocks.RBACManager) {
				rbacMgr.EXPECT().GetUserRole(ctx, appID, userID).
					Once().
					Return(rbac.Role("admin"), fmt.Errorf("cache update error"))
			},
			expectedError: nil,
			expectedRole:  "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacMgr := mocks.NewRBACManager(t)

			tt.mockBehavior(rbacMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, rbacMgr, nil, nil, nil, nil, nil, nil)

			role, err := user.GetUserRole(ctx, appID, userID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedRole, role)
			}
		})
	}
}

func TestUserUsecase_ChangeUserRole(t *testing.T) {
	ctx := context.Background()
	appID := "test-app-id"
	userID := "test-user-id"
	newRole := "admin"

	tests := []struct {
		name          string
		mockBehavior  func(rbacMgr *mocks.RBACManager)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(rbacMgr *mocks.RBACManager) {
				rbacMgr.EXPECT().SetUserRole(ctx, appID, userID, rbac.Role(newRole)).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Failed to set user role",
			mockBehavior: func(rbacMgr *mocks.RBACManager) {
				rbacMgr.EXPECT().SetUserRole(ctx, appID, userID, rbac.Role(newRole)).
					Once().
					Return(fmt.Errorf("rbac manager error"))
			},
			expectedError: domain.ErrFailedToSetUserRole,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacMgr := mocks.NewRBACManager(t)

			tt.mockBehavior(rbacMgr)

			log := slogdiscard.NewDiscardLogger()

			user := NewUsecase(log, nil, rbacMgr, nil, nil, nil, nil, nil, nil)

			err := user.ChangeUserRole(ctx, appID, userID, newRole)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
