package verification

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/domain/service/verification/mocks"
	"github.com/rshelekhov/sso/internal/infrastructure/storage"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCreateToken(t *testing.T) {
	mockVerificationStorage := new(mocks.Storage)
	tokenExpiryTime := 24 * time.Hour

	verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

	ctx := context.Background()
	user := entity.User{
		ID:    "test-user-id",
		AppID: "test-app-id",
		Email: "test-email@gmail.com",
	}
	verificationEndpoint := "https://example.com/verify"
	tokenType := entity.TokenTypeVerifyEmail

	originalRandReader := rand.Reader
	defer func() {
		rand.Reader = originalRandReader
	}()

	t.Run("Success", func(t *testing.T) {
		rand.Reader = mockRandReader{
			readFunc: func(b []byte) (int, error) {
				for i := range b {
					b[i] = byte(i)
				}
				return len(b), nil
			},
		}

		mockVerificationStorage.
			On("SaveVerificationToken", ctx, mock.AnythingOfType("entity.VerificationToken")).
			Once().
			Return(nil)

		token, err := verificationService.CreateToken(ctx, user, verificationEndpoint, tokenType)

		require.NoError(t, err)
		require.NotEmpty(t, token.Token)
		require.Equal(t, verificationEndpoint, token.Endpoint)
		require.Equal(t, user.ID, token.UserID)
		require.Equal(t, tokenType, token.Type)
		require.False(t, token.ExpiresAt.IsZero())
	})

	t.Run("Error – Failed to generate verification token", func(t *testing.T) {
		rand.Reader = mockRandReader{
			readFunc: func(b []byte) (int, error) {
				return 0, errors.New("random generation error")
			},
		}

		token, err := verificationService.CreateToken(ctx, user, verificationEndpoint, tokenType)
		require.Error(t, err)
		require.ErrorIs(t, err, domain.ErrFailedToGenerateVerificationToken)
		require.Empty(t, token)
	})

	t.Run("Error – Failed to save verification token", func(t *testing.T) {
		rand.Reader = mockRandReader{
			readFunc: func(b []byte) (int, error) {
				for i := range b {
					b[i] = byte(i)
				}
				return len(b), nil
			},
		}

		mockVerificationStorage.
			On("SaveVerificationToken", ctx, mock.AnythingOfType("entity.VerificationToken")).
			Once().
			Return(errors.New("storage error"))

		token, err := verificationService.CreateToken(ctx, user, verificationEndpoint, tokenType)

		require.Error(t, err)
		require.ErrorIs(t, err, domain.ErrFailedToSaveVerificationToken)
		require.Empty(t, token)
	})
}

func TestGetTokenData(t *testing.T) {
	mockVerificationStorage := new(mocks.Storage)
	tokenExpiryTime := 24 * time.Hour

	verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		expectedTokenData := entity.VerificationToken{
			Token:     "test-token",
			UserID:    "test-user-id",
			AppID:     "test-app-id",
			Endpoint:  "https://example.com/verify",
			Email:     "test-email@gmail.com",
			Type:      entity.TokenTypeVerifyEmail,
			ExpiresAt: time.Now().Add(tokenExpiryTime),
		}

		mockVerificationStorage.
			On("GetVerificationTokenData", ctx, "test-token").
			Once().
			Return(expectedTokenData, nil)

		token, err := verificationService.GetTokenData(ctx, "test-token")
		require.Equal(t, expectedTokenData.Token, token.Token)
		require.Equal(t, expectedTokenData.UserID, token.UserID)
		require.Equal(t, expectedTokenData.AppID, token.AppID)
		require.Equal(t, expectedTokenData.Endpoint, token.Endpoint)
		require.Equal(t, expectedTokenData.Email, token.Email)
		require.Equal(t, expectedTokenData.Type, token.Type)
		require.Equal(t, expectedTokenData.ExpiresAt, token.ExpiresAt)
		require.NoError(t, err)
	})

	t.Run("Error – Token not found", func(t *testing.T) {
		mockVerificationStorage.
			On("GetVerificationTokenData", ctx, "test-token").
			Once().
			Return(entity.VerificationToken{}, storage.ErrVerificationTokenNotFound)

		token, err := verificationService.GetTokenData(ctx, "test-token")
		require.Empty(t, token)
		require.ErrorIs(t, err, domain.ErrVerificationTokenNotFound)
	})

	t.Run("Error – Failed to get verification token data", func(t *testing.T) {
		mockVerificationStorage.
			On("GetVerificationTokenData", ctx, "test-token").
			Once().
			Return(entity.VerificationToken{}, errors.New("storage error"))

		token, err := verificationService.GetTokenData(ctx, "test-token")
		require.Empty(t, token)
		require.ErrorIs(t, err, domain.ErrFailedToGetVerificationTokenData)
	})
}

func TestDeleteToken(t *testing.T) {
	mockVerificationStorage := new(mocks.Storage)
	tokenExpiryTime := 24 * time.Hour

	verificationService := NewService(tokenExpiryTime, mockVerificationStorage)

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockVerificationStorage.
			On("DeleteVerificationToken", ctx, "test-token").
			Once().
			Return(nil)

		err := verificationService.DeleteToken(ctx, "test-token")
		require.NoError(t, err)
	})

	t.Run("Error – Failed to delete verification token", func(t *testing.T) {
		mockVerificationStorage.
			On("DeleteVerificationToken", ctx, "test-token").
			Once().
			Return(errors.New("storage error"))

		err := verificationService.DeleteToken(ctx, "test-token")
		require.Error(t, err)
		require.ErrorIs(t, err, domain.ErrFailedToDeleteVerificationToken)
	})
}

type mockRandReader struct {
	readFunc func([]byte) (int, error)
}

func (m mockRandReader) Read(p []byte) (n int, err error) {
	return m.readFunc(p)
}
