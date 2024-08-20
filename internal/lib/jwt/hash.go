package jwt

import (
	"crypto/rand"
	"fmt"
	"github.com/rshelekhov/sso/internal/config/settings"
	"io"
)

func PasswordHash(password string, params settings.PasswordHashParams) (string, error) {
	const method = "jwt.PasswordHash"

	if password == "" {
		return "", fmt.Errorf("%s: password is empty", method)
	}

	salt, err := generateSalt(params.SaltLength)
	if err != nil {
		return "", err
	}

	if params.Type == settings.PasswordHashDefault {
		params = settings.DefaultPasswordHashParams
	}

	var hash string
	switch params.Type {
	case settings.PasswordHashDefault, settings.PasswordHashArgon2:
		hash = PasswordHashArgon2(password, *params.Argon, salt, []byte(params.Pepper))
	case settings.PasswordHashBcrypt:
		hash, err = PasswordHashBcrypt(password, *params.Bcrypt, []byte(params.Pepper))
	default:
		return "", fmt.Errorf("%s: unsupported password hash type: %s", method, params.Type)
	}
	if err != nil {
		return "", err
	}
	return hash, nil
}

func PasswordMatch(hash, password string, params settings.PasswordHashParams) (bool, error) {
	const method = "jwt.PasswordMatch"

	if hash == "" {
		return false, fmt.Errorf("%s: hash is empty", method)
	} else if password == "" {
		return false, fmt.Errorf("%s: password is empty", method)
	}

	switch {
	case params.Type == settings.PasswordHashDefault:
		return PasswordMatchArgon2(hash, password, []byte(params.Pepper))
	case params.Type == settings.PasswordHashArgon2:
		return PasswordMatchArgon2(hash, password, []byte(params.Pepper))
	case params.Type == settings.PasswordHashBcrypt:
		return PasswordMatchBcrypt(hash, password, []byte(params.Pepper))
	default:
		return false, fmt.Errorf("%s: unsupported password hash type: %s", method, params.Type)
	}
}

func generateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	return salt, err
}
