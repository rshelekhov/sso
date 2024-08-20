package jwt

import (
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPasswordHashBcrypt_HappyPath(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := PasswordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
}

func TestPasswordMatchBcrypt_HappyPath(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := PasswordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)

	matched, err := PasswordMatchBcrypt(hash, pass, pepper)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPasswordMatchBcrypt_IncorrectPassword(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := PasswordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)

	matched, err := PasswordMatchBcrypt(hash, "incorrect-password", pepper)
	require.NoError(t, err)
	require.False(t, matched)
}
