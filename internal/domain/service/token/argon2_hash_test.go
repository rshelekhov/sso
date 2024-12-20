package token

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPasswordHashArgon2_HappyPath(t *testing.T) {
	pass := "test-password"
	params := defaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := passwordHashArgon2(pass, params, salt, pepper)
	require.NotEmpty(t, hash)

	assert.Contains(t, hash, "$argon2$")
	assert.Contains(t, hash, "$v=")
	assert.Contains(t, hash, "$m=")
	assert.Contains(t, hash, ",t=")
	assert.Contains(t, hash, ",p=")
	assert.Contains(t, hash, base64.RawStdEncoding.EncodeToString(salt))
}

func TestPasswordMatchArgon2_HappyPath(t *testing.T) {
	pass := "test-password"
	params := defaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := passwordHashArgon2(pass, params, salt, pepper)
	require.NotEmpty(t, hash)

	matched, err := passwordMatchArgon2(hash, pass, pepper)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPasswordMatchArgon2_IncorrectPassword(t *testing.T) {
	params := defaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := passwordHashArgon2("test-password", params, salt, pepper)
	require.NotEmpty(t, hash)

	matched, _ := passwordMatchArgon2(hash, "incorrect-password", pepper)
	require.False(t, matched)
}

func TestPasswordMatchArgon2_EmptyPassword(t *testing.T) {
	params := defaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := passwordHashArgon2("test-password", params, salt, pepper)
	require.NotEmpty(t, hash)

	matched, _ := passwordMatchArgon2(hash, "", pepper)
	require.False(t, matched)

}
