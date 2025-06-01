package verification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/verification/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestVerificationService_CreateToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		mockBehavior  func(*mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().SaveVerificationToken(ctx, mock.AnythingOfType("entity.VerificationToken")).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error – Failed to save verification token",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().SaveVerificationToken(ctx, mock.AnythingOfType("entity.VerificationToken")).
					Once().
					Return(errors.New("storage error"))
			},
			expectedError: domain.ErrFailedToSaveVerificationToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := entity.User{
				ID:    "test-user-id",
				AppID: "test-app-id",
				Email: "test-email@gmail.com",
			}
			tokenType := entity.TokenTypeVerifyEmail
			verificationEndpoint := "https://example.com/verify"
			mockVerificationStorage := new(mocks.Storage)
			tt.mockBehavior(mockVerificationStorage)
			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			token, err := verificationService.CreateToken(ctx, user, verificationEndpoint, tokenType)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, token)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, token.Token)
				require.Equal(t, verificationEndpoint, token.Endpoint)
				require.Equal(t, user.ID, token.UserID)
				require.Equal(t, tokenType, token.Type)
				require.False(t, token.ExpiresAt.IsZero())
			}
		})
	}
}

func TestVerificationService_GetTokenData(t *testing.T) {
	ctx := context.Background()
	tokenStr := "test-verification-token"

	verificationToken := entity.VerificationToken{
		Token:    tokenStr,
		UserID:   "test-user-id",
		AppID:    "test-app-id",
		Endpoint: "https://example.com/verify",
		Email:    "test-email@gmail.com",
		Type:     entity.TokenTypeVerifyEmail,
	}

	tests := []struct {
		name          string
		mockBehavior  func(*mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().GetVerificationTokenData(ctx, tokenStr).
					Once().
					Return(verificationToken, nil)
			},
			expectedError: nil,
		},
		{
			name: "Error – Token not found",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().GetVerificationTokenData(ctx, tokenStr).
					Once().
					Return(entity.VerificationToken{}, storage.ErrVerificationTokenNotFound)
			},
			expectedError: domain.ErrVerificationTokenNotFound,
		},
		{
			name: "Error – Failed to get verification token data",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().GetVerificationTokenData(ctx, tokenStr).
					Once().
					Return(entity.VerificationToken{}, errors.New("verification storage error"))
			},
			expectedError: domain.ErrFailedToGetVerificationTokenData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVerificationStorage := new(mocks.Storage)
			tt.mockBehavior(mockVerificationStorage)

			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			tokenData, err := verificationService.GetTokenData(ctx, tokenStr)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, tokenData)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, tokenData)
			}
		})
	}
}

func TestVerificationService_DeleteToken(t *testing.T) {
	ctx := context.Background()
	tokenStr := "test-verification-token"

	tests := []struct {
		name          string
		mockBehavior  func(*mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().DeleteVerificationToken(ctx, tokenStr).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error – Failed to delete verification token",
			mockBehavior: func(mockVerificationStorage *mocks.Storage) {
				mockVerificationStorage.EXPECT().DeleteVerificationToken(ctx, tokenStr).
					Once().
					Return(errors.New("verification storage error"))
			},
			expectedError: domain.ErrFailedToDeleteVerificationToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVerificationStorage := new(mocks.Storage)
			tt.mockBehavior(mockVerificationStorage)

			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			err := verificationService.DeleteToken(ctx, tokenStr)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerificationService_DeleteAllTokens(t *testing.T) {
	appID := "test-app-id"
	userID := "test-user-id"

	tests := []struct {
		name          string
		mockBehavior  func(verificationStorage *mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().
					DeleteAllTokens(context.Background(), appID, userID).
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error - Storage error",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().
					DeleteAllTokens(context.Background(), appID, userID).
					Return(errors.New("verification storage error"))
			},
			expectedError: errors.New("verification storage error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVerificationStorage := new(mocks.Storage)
			tt.mockBehavior(mockVerificationStorage)

			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			err := verificationService.DeleteAllTokens(context.Background(), appID, userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
