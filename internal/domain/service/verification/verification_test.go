package verification

import (
	"context"
	"crypto/rand"
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
		name           string
		mockBehavior   func(*mocks.Storage)
		mockRandReader func() func([]byte) (int, error)
		expectedError  error
	}{
		{
			name: "Success",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().SaveVerificationToken(ctx, mock.AnythingOfType("entity.VerificationToken")).
					Once().
					Return(nil)
			},
			mockRandReader: func() func([]byte) (int, error) {
				return func(b []byte) (int, error) {
					for i := range b {
						b[i] = byte(i)
					}
					return len(b), nil
				}
			},
			expectedError: nil,
		},
		{
			name:         "Error – Failed to generate verification token",
			mockBehavior: func(*mocks.Storage) {},
			mockRandReader: func() func([]byte) (int, error) {
				return func([]byte) (int, error) {
					return 0, errors.New("random generation error")
				}
			},
			expectedError: domain.ErrFailedToGenerateVerificationToken,
		},
		{
			name: "Error – Failed to save verification token",
			mockBehavior: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().SaveVerificationToken(ctx, mock.AnythingOfType("entity.VerificationToken")).
					Once().
					Return(errors.New("storage error"))
			},
			mockRandReader: func() func([]byte) (int, error) {
				return func(b []byte) (int, error) {
					for i := range b {
						b[i] = byte(i)
					}
					return len(b), nil
				}
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
			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			if tt.mockBehavior != nil {
				tt.mockBehavior(mockVerificationStorage)
			}

			if tt.mockRandReader != nil {
				rand.Reader = mockRandReader{readFunc: tt.mockRandReader()}
				defer func() { rand.Reader = rand.Reader }()
			}

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
			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			if tt.mockBehavior != nil {
				tt.mockBehavior(mockVerificationStorage)
			}

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
		setup         func(*mocks.Storage)
		expectedError error
	}{
		{
			name: "Success",
			setup: func(verificationStorage *mocks.Storage) {
				verificationStorage.EXPECT().DeleteVerificationToken(ctx, tokenStr).
					Once().
					Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "Error – Failed to delete verification token",
			setup: func(mockVerificationStorage *mocks.Storage) {
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
			tokenExpiryTime := 24 * time.Hour
			verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

			if tt.setup != nil {
				tt.setup(mockVerificationStorage)
			}

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

type mockRandReader struct {
	readFunc func([]byte) (int, error)
}

func (m mockRandReader) Read(p []byte) (n int, err error) {
	return m.readFunc(p)
}
