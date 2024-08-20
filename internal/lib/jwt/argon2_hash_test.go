package jwt

import (
	"encoding/base64"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPasswordHashArgon2_HappyPath(t *testing.T) {
	pass := "test-password"
	params := settings.DefaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := PasswordHashArgon2(pass, params, salt, pepper)
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
	params := settings.DefaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := PasswordHashArgon2(pass, params, salt, pepper)
	require.NotEmpty(t, hash)

	matched, err := PasswordMatchArgon2(hash, pass, pepper)
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPasswordMatchArgon2_IncorrectPassword(t *testing.T) {
	params := settings.DefaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := PasswordHashArgon2("test-password", params, salt, pepper)
	require.NotEmpty(t, hash)

	matched, _ := PasswordMatchArgon2(hash, "incorrect-password", pepper)
	require.False(t, matched)

}

func TestPasswordMatchArgon2_EmptyPassword(t *testing.T) {
	params := settings.DefaultPasswordHashArgon2Params
	salt := []byte("salt")
	pepper := []byte("pepper")

	hash := PasswordHashArgon2("test-password", params, salt, pepper)
	require.NotEmpty(t, hash)

	matched, _ := PasswordMatchArgon2(hash, "", pepper)
	require.False(t, matched)

}
