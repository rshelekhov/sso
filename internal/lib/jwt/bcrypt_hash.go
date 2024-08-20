package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"github.com/rshelekhov/sso/internal/config/settings"
	"golang.org/x/crypto/bcrypt"
)

func PasswordHashBcrypt(password string, p settings.PasswordHashBcryptParams, pepper []byte) (string, error) {
	passwordHmac := hmac.New(sha256.New, pepper)
	_, err := passwordHmac.Write([]byte(password))
	if err != nil {
		return "", err
	}

	passwordBcrypt, err := bcrypt.GenerateFromPassword(passwordHmac.Sum(nil), p.Cost)
	if err != nil {
		return "", err
	}

	return string(passwordBcrypt), nil
}

func PasswordMatchBcrypt(hash, password string, pepper []byte) (bool, error) {
	passwordHmac := hmac.New(sha256.New, pepper)
	_, err := passwordHmac.Write([]byte(password))
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), passwordHmac.Sum(nil))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}
