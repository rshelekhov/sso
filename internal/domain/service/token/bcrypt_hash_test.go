package token

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenService_PasswordHashBcrypt_HappyPath(t *testing.T) {
	pass := "test-password"
	params := DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := passwordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
}

func TestTokenService_PasswordMatchBcrypt_HappyPath(t *testing.T) {
	pass := "test-password"
	params := DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := passwordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)

	matched, err := passwordMatchBcrypt(hash, pass, pepper)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestTokenService_PasswordMatchBcrypt_IncorrectPassword(t *testing.T) {
	pass := "test-password"
	params := DefaultPasswordHashBcryptParams
	pepper := []byte("pepper")

	hash, err := passwordHashBcrypt(pass, params, pepper)
	require.NoError(t, err)

	matched, err := passwordMatchBcrypt(hash, "incorrect-password", pepper)
	require.NoError(t, err)
	require.False(t, matched)
}
