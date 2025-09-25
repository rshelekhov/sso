package user_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/usecase/user"
	"github.com/rshelekhov/sso/internal/domain/usecase/user/mocks"
	"github.com/rshelekhov/sso/internal/lib/logger/slogdiscard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUserUsecase_GetUser(t *testing.T) {
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"
	userID := "test-user-id"

	expectedUser := entity.User{
		ID:        userID,
		Email:     "test@example.com",
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserByID(ctx, userID).
					Once().
					Return(expectedUser, nil)
			},
			expectedError: nil,
			expectedUser:  expectedUser,
		},
		{
			name: "Failed to extract user ID",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return("", domain.ErrFailedToExtractUserIDFromContext)
			},
			expectedError: domain.ErrFailedToExtractUserIDFromContext,
			expectedUser:  entity.User{},
		},
		{
			name: "User not found",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserByID(ctx, userID).
					Once().
					Return(entity.User{}, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
			expectedUser:  entity.User{},
		},
		{
			name: "Failed to get user",
			mockBehavior: func(identityMgr *mocks.IdentityManager, userMgr *mocks.UserdataManager) {
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserByID(ctx, userID).
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

			userUsecase := user.NewUsecase(log, nil, nil, userMgr, nil, identityMgr, nil, nil, &mocks.NoOpMetricsRecorder{})

			userData, err := userUsecase.GetUser(context.Background(), clientID)

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
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"
	userID := "test-user-id"

	expectedUser := entity.User{
		ID:        userID,
		Email:     "test@example.com",
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
				userMgr.EXPECT().GetUserByID(ctx, userID).
					Once().
					Return(expectedUser, nil)
			},
			expectedError: nil,
			expectedUser:  expectedUser,
		},
		{
			name: "User not found",
			mockBehavior: func(userMgr *mocks.UserdataManager) {
				userMgr.EXPECT().GetUserByID(ctx, userID).
					Once().
					Return(entity.User{}, domain.ErrUserNotFound)
			},
			expectedError: domain.ErrUserNotFound,
			expectedUser:  entity.User{},
		},
		{
			name: "Failed to get user",
			mockBehavior: func(userMgr *mocks.UserdataManager) {
				userMgr.EXPECT().GetUserByID(ctx, userID).
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

			userUsecase := user.NewUsecase(log, nil, nil, userMgr, nil, nil, nil, nil, &mocks.NoOpMetricsRecorder{})

			userData, err := userUsecase.GetUserByID(context.Background(), clientID, userID)

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
	ctx := mock.Anything
	clientID := "test-app-id"
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
					Once().
					Return(existingUser, nil)

				userMgr.EXPECT().GetUserStatusByEmail(ctx, newEmail).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
					Once().
					Return(existingUser, nil)

				userMgr.EXPECT().GetUserStatusByEmail(ctx, newEmail).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
					Once().
					Return(existingUser, nil)

				userMgr.EXPECT().GetUserStatusByEmail(ctx, newEmail).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				userMgr.EXPECT().GetUserData(ctx, userID).
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

			userUsecase := user.NewUsecase(log, nil, nil, userMgr, passwordMgr, identityMgr, nil, nil, &mocks.NoOpMetricsRecorder{})

			updatedUser, err := userUsecase.UpdateUser(context.Background(), clientID, tt.reqData)

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
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				verificationMgr.EXPECT().DeleteAllTokens(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
					Once().
					Return(userID, nil)

				txMgr.EXPECT().WithinTransaction(ctx, mock.AnythingOfType("func(context.Context) error")).
					RunAndReturn(func(ctx context.Context, fn func(context.Context) error) error {
						return fn(ctx)
					})

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				verificationMgr.EXPECT().DeleteAllTokens(ctx, userID).
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
				identityMgr.EXPECT().ExtractUserIDFromTokenInContext(ctx, clientID).
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

			userUsecase := user.NewUsecase(log, nil, sessionMgr, userMgr, nil, identityMgr, verificationMgr, txMgr, &mocks.NoOpMetricsRecorder{})

			err := userUsecase.DeleteUser(context.Background(), clientID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUserUsecase_DeleteUserByID(t *testing.T) {
	ctx := mock.MatchedBy(func(context.Context) bool { return true })
	clientID := "test-app-id"
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				verificationMgr.EXPECT().DeleteAllTokens(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				userMgr.EXPECT().GetUserStatusByID(ctx, userID).
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

				verificationMgr.EXPECT().DeleteAllTokens(ctx, userID).
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

			userUsecase := user.NewUsecase(log, nil, sessionMgr, userMgr, nil, nil, verificationMgr, txMgr, &mocks.NoOpMetricsRecorder{})

			err := userUsecase.DeleteUserByID(context.Background(), clientID, userID)

			if tt.expectedError != nil {
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
