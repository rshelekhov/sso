package token

import (
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTokenService_HashPassword(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		config        Config
		expectedError error
	}{
		{
			name:     "Valid password with Argon2",
			password: "test-password",
			config: Config{
				PasswordHashParams: PasswordHashParams{
					Type:       PasswordHashArgon2,
					SaltLength: 32,
					Pepper:     "pepper",
					Argon:      &defaultPasswordHashArgon2Params,
				},
			},
			expectedError: nil,
		},
		{
			name:     "Valid password with Bcrypt",
			password: "test-password",
			config: Config{
				PasswordHashParams: PasswordHashParams{
					Type:       PasswordHashBcrypt,
					SaltLength: 32,
					Pepper:     "pepper",
					Bcrypt:     &defaultPasswordHashBcryptParams,
				},
			},
			expectedError: nil,
		},
		{
			name:     "Empty password",
			password: "",
			config: Config{
				PasswordHashParams: defaultPasswordHashParams,
			},
			expectedError: domain.ErrPasswordIsNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKeyStorage := new(mocks.KeyStorage)
			tokenService := NewService(tt.config, mockKeyStorage)

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
		config         Config
		setupHash      bool
		expectedMatch  bool
		expectedError  error
	}{
		{
			name:     "Success with Argon2",
			password: password,
			config: Config{
				PasswordHashParams: PasswordHashParams{
					Type:       PasswordHashArgon2,
					SaltLength: 32,
					Pepper:     "pepper",
					Argon:      &defaultPasswordHashArgon2Params,
				},
			},
			setupHash:     true,
			expectedMatch: true,
		},
		{
			name:     "Success with Bcrypt",
			password: password,
			config: Config{
				PasswordHashParams: PasswordHashParams{
					Type:       PasswordHashBcrypt,
					SaltLength: 32,
					Pepper:     "pepper",
					Bcrypt:     &defaultPasswordHashBcryptParams,
				},
			},
			setupHash:     true,
			expectedMatch: true,
		},
		{
			name:           "Empty hash",
			hashedPassword: "",
			password:       "test-password",
			config: Config{
				PasswordHashParams: defaultPasswordHashParams,
			},
			expectedMatch: false,
			expectedError: domain.ErrHashIsNotAllowed,
		},
		{
			name:     "Empty password",
			password: "",
			config: Config{
				PasswordHashParams: defaultPasswordHashParams,
			},
			setupHash:     true,
			expectedMatch: false,
			expectedError: domain.ErrPasswordIsNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKeyStorage := new(mocks.KeyStorage)
			tokenService := NewService(tt.config, mockKeyStorage)

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
