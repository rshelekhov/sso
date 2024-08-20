package jwt

import (
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPasswordHash_HappyPath(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashParams

	hash, err := PasswordHash(pass, params)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
}

func TestPasswordHash_EmptyPassword(t *testing.T) {
	pass := ""
	params := settings.DefaultPasswordHashParams

	hash, err := PasswordHash(pass, params)
	require.Error(t, err)
	require.Empty(t, hash)
}

func TestPasswordMatch_HappyPath(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashParams

	hash, err := PasswordHash(pass, params)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	matched, err := PasswordMatch(hash, pass, params)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPasswordMatch_EmptyHash(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := PasswordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	matched, err := PasswordMatchBcrypt("", pass, pepper)
	require.Error(t, err)
	require.False(t, matched)
}
