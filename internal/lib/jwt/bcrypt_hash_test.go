package jwt

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPasswordHashBcryptHappyPath(t *testing.T) {
	pass := "test-password"
	cost := 10
	salt := []byte("salt")

	hash, err := PasswordHashBcrypt(pass, cost, salt)
	require.NoError(t, err)
	require.NotEmpty(t, hash)
}

func TestPasswordHashBcryptFailCases(t *testing.T) {
	pass := "test-password"
	cost := 10
	salt := []byte("salt")

	tests := []struct {
		name string
		pass string
		cost int
		salt []byte
	}{
		{
			name: "password is empty",
			pass: "",
			cost: cost,
			salt: salt,
		},
		{
			name: "salt is empty",
			pass: pass,
			cost: cost,
			salt: []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PasswordHashBcrypt(tt.pass, tt.cost, tt.salt)
			require.Error(t, err)
		})
	}
}

func TestPasswordMatchHappyPath(t *testing.T) {
	pass := "test-password"

	hash, err := PasswordHashBcrypt(pass, 10, []byte("salt"))
	require.NoError(t, err)

	matched, err := PasswordMatch(hash, pass, []byte("salt"))
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPasswordMatchFailCase(t *testing.T) {
	pass := "test-password"
	cost := 10
	salt := []byte("salt")

	hash, err := PasswordHashBcrypt(pass, cost, salt)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	tests := []struct {
		name string
		hash string
		pass string
		salt []byte
	}{
		{
			name: "hash is empty",
			hash: "",
			pass: pass,
			salt: salt,
		},
		{
			name: "password is empty",
			hash: hash,
			pass: "",
			salt: salt,
		},
		{
			name: "salt is empty",
			hash: hash,
			pass: pass,
			salt: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := PasswordMatch(tt.hash, tt.pass, tt.salt)
			require.Error(t, err)
			require.False(t, matched)
		})
	}
}
