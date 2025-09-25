package token_test

import (
	"testing"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/token"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/require"
)

func TestTokenService_HashPassword(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		config        token.Config
		expectedError error
	}{
		{
			name:     "Valid password with Argon2",
			password: "test-password",
			config: token.Config{
				PasswordHashParams: token.PasswordHashParams{
					Type:       token.PasswordHashArgon2,
					SaltLength: 32,
					Pepper:     "pepper",
					Argon:      &token.DefaultPasswordHashArgon2Params,
				},
			},
			expectedError: nil,
		},
		{
			name:     "Valid password with Bcrypt",
			password: "test-password",
			config: token.Config{
				PasswordHashParams: token.PasswordHashParams{
					Type:       token.PasswordHashBcrypt,
					SaltLength: 32,
					Pepper:     "pepper",
					Bcrypt:     &token.DefaultPasswordHashBcryptParams,
				},
			},
			expectedError: nil,
		},
		{
			name:     "Empty password",
			password: "",
			config: token.Config{
				PasswordHashParams: token.DefaultPasswordHashParams,
			},
			expectedError: domain.ErrPasswordIsNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKeyStorage := new(mocks.KeyStorage)
			tokenService := token.NewService(tt.config, mockKeyStorage, &mocks.NoOpMetricsRecorder{})

			hashedPassword, err := tokenService.HashPassword(tt.password)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, hashedPassword)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, hashedPassword)
				require.Greater(t, len(hashedPassword), 0)
			}
		})
	}
}

func TestTokenService_PasswordMatch(t *testing.T) {
	password := "test-password"

	tests := []struct {
		name           string
		hashedPassword string
		password       string
		config         token.Config
		setupHash      bool
		expectedMatch  bool
		expectedError  error
	}{
		{
			name:     "Success with Argon2",
			password: password,
			config: token.Config{
				PasswordHashParams: token.PasswordHashParams{
					Type:       token.PasswordHashArgon2,
					SaltLength: 32,
					Pepper:     "pepper",
					Argon:      &token.DefaultPasswordHashArgon2Params,
				},
			},
			setupHash:     true,
			expectedMatch: true,
		},
		{
			name:     "Success with Bcrypt",
			password: password,
			config: token.Config{
				PasswordHashParams: token.PasswordHashParams{
					Type:       token.PasswordHashBcrypt,
					SaltLength: 32,
					Pepper:     "pepper",
					Bcrypt:     &token.DefaultPasswordHashBcryptParams,
				},
			},
			setupHash:     true,
			expectedMatch: true,
		},
		{
			name:           "Empty hash",
			hashedPassword: "",
			password:       "test-password",
			config: token.Config{
				PasswordHashParams: token.DefaultPasswordHashParams,
			},
			expectedMatch: false,
			expectedError: domain.ErrHashIsNotAllowed,
		},
		{
			name:     "Empty password",
			password: "",
			config: token.Config{
				PasswordHashParams: token.DefaultPasswordHashParams,
			},
			setupHash:     true,
			expectedMatch: false,
			expectedError: domain.ErrPasswordIsNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKeyStorage := new(mocks.KeyStorage)
			tokenService := token.NewService(tt.config, mockKeyStorage, &mocks.NoOpMetricsRecorder{})

			var hashedPassword string
			if tt.setupHash {
				var err error
				hashedPassword, err = tokenService.HashPassword(password)
				require.NoError(t, err)
				require.NotEmpty(t, hashedPassword)
			} else {
				hashedPassword = tt.hashedPassword
			}

			matched, err := tokenService.PasswordMatch(hashedPassword, tt.password)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.False(t, matched)
			} else {
				require.NoError(t, err)
				require.True(t, matched)
			}
		})
	}
}
