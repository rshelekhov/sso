package token

import (
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHashPassword(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)

	t.Run("Valid password with Argon2", func(t *testing.T) {
		cfg := Config{
			PasswordHashParams: PasswordHashParams{
				Type:       PasswordHashArgon2,
				SaltLength: 32,
				Pepper:     "pepper",
				Argon:      &defaultPasswordHashArgon2Params,
			},
		}

		tokenService := NewService(cfg, mockKeyStorage)

		hashedPassword, err := tokenService.HashPassword("test-password")

		require.NoError(t, err)
		assert.NotEmpty(t, hashedPassword)

		assert.Greater(t, len(hashedPassword), 0)
	})

	t.Run("Valid password with Bcrypt", func(t *testing.T) {
		cfg := Config{
			PasswordHashParams: PasswordHashParams{
				Type:       PasswordHashBcrypt,
				SaltLength: 32,
				Pepper:     "pepper",
				Bcrypt:     &defaultPasswordHashBcryptParams,
			},
		}

		tokenService := NewService(cfg, mockKeyStorage)

		hashedPassword, err := tokenService.HashPassword("test-password")

		require.NoError(t, err)
		assert.NotEmpty(t, hashedPassword)

		assert.Greater(t, len(hashedPassword), 0)
	})

	t.Run("Empty password", func(t *testing.T) {
		cfg := Config{
			PasswordHashParams: defaultPasswordHashParams,
		}

		tokenService := NewService(cfg, mockKeyStorage)

		hashedPassword, err := tokenService.HashPassword("")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), domain.ErrPasswordIsNotAllowed.Error())
		assert.Empty(t, hashedPassword)
	})
}

func TestPasswordMatch(t *testing.T) {
	mockKeyStorage := new(mocks.KeyStorage)
	password := "test-password"

	t.Run("Success with Argon2", func(t *testing.T) {
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
	})

	t.Run("Success with Bcrypt", func(t *testing.T) {
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
	})

	t.Run("Empty hash", func(t *testing.T) {
		cfg := Config{
			PasswordHashParams: defaultPasswordHashParams,
		}

		tokenService := NewService(cfg, mockKeyStorage)

		matched, err := tokenService.PasswordMatch("", "test-password")

		assert.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrHashIsNotAllowed)
		assert.Equal(t, false, matched)
	})

	t.Run("Empty password", func(t *testing.T) {
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
	})
}
