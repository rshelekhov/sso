package token

import (
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHashPassword_HappyPath(t *testing.T) {
	testCases := []struct {
		name           string
		password       string
		passwordParams PasswordHashParams
	}{
		{
			name:     "Valid password with Argon2",
			password: "test-password",
			passwordParams: PasswordHashParams{
				Type:       PasswordHashArgon2,
				SaltLength: 32,
				Pepper:     "pepper",
				Argon:      &defaultPasswordHashArgon2Params,
			},
		},
		{
			name:     "Valid password with Bcrypt",
			password: "test-password",
			passwordParams: PasswordHashParams{
				Type:       PasswordHashBcrypt,
				SaltLength: 32,
				Pepper:     "pepper",
				Bcrypt:     &defaultPasswordHashBcryptParams,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKeyStorage := new(mocks.KeyStorage)

			cfg := Config{
				PasswordHashParams: tc.passwordParams,
			}

			tokenService := NewService(cfg, mockKeyStorage)

			hashedPassword, err := tokenService.HashPassword(tc.password)

			require.NoError(t, err)
			assert.NotEmpty(t, hashedPassword)

			assert.Greater(t, len(hashedPassword), 0)
		})
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := Config{
		PasswordHashParams: defaultPasswordHashParams,
	}

	tokenService := NewService(cfg, mockKeyStorage)

	hashedPassword, err := tokenService.HashPassword("")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), domain.ErrPasswordIsNotAllowed.Error())
	assert.Empty(t, hashedPassword)

}

func TestPasswordMatch_HappyPathWithArgon2(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)
	password := "test-password"

	cfg := Config{
		PasswordHashParams: PasswordHashParams{
			Type:       PasswordHashArgon2,
			SaltLength: 32,
			Pepper:     "pepper",
			Argon:      &defaultPasswordHashArgon2Params,
		},
	}

	tokenService := NewService(cfg, mockKeyStorage)

	hashedPassword, err := tokenService.HashPassword(password)

	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword)

	matched, err := tokenService.PasswordMatch(hashedPassword, password)

	require.NoError(t, err)
	require.True(t, matched)

}

func TestPasswordMatch_HappyPathWithBcrypt(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)
	password := "test-password"

	cfg := Config{
		PasswordHashParams: PasswordHashParams{
			Type:       PasswordHashBcrypt,
			SaltLength: 32,
			Pepper:     "pepper",
			Bcrypt:     &defaultPasswordHashBcryptParams,
		},
	}

	tokenService := NewService(cfg, mockKeyStorage)

	hashedPassword, err := tokenService.HashPassword(password)

	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword)

	matched, err := tokenService.PasswordMatch(hashedPassword, password)

	require.NoError(t, err)
	require.True(t, matched)

}

func TestPasswordMatch_EmptyHash(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)

	cfg := Config{
		PasswordHashParams: defaultPasswordHashParams,
	}

	tokenService := NewService(cfg, mockKeyStorage)

	matched, err := tokenService.PasswordMatch("", "test-password")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), domain.ErrHashIsNotAllowed.Error())
	assert.Equal(t, false, matched)
}

func TestPasswordMatch_EmptyPassword(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)
	password := "test-password"

	cfg := Config{
		PasswordHashParams: defaultPasswordHashParams,
	}

	tokenService := NewService(cfg, mockKeyStorage)

	hashedPassword, err := tokenService.HashPassword(password)

	require.NoError(t, err)
	require.NotEmpty(t, hashedPassword)

	matched, err := tokenService.PasswordMatch(hashedPassword, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), domain.ErrPasswordIsNotAllowed.Error())
	assert.Equal(t, false, matched)
}
