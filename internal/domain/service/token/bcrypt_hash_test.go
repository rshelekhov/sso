package token

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPasswordHashBcrypt_HappyPath(t *testing.T) {
	pass := "test-password"
	params := defaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := passwordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
}

func TestPasswordMatchBcrypt_HappyPath(t *testing.T) {
	pass := "test-password"
	params := defaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := passwordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)

	matched, err := passwordMatchBcrypt(hash, pass, pepper)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPasswordMatchBcrypt_IncorrectPassword(t *testing.T) {
	pass := "test-password"
	params := defaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := passwordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)

	matched, err := passwordMatchBcrypt(hash, "incorrect-password", pepper)
	require.NoError(t, err)
	require.False(t, matched)
}
