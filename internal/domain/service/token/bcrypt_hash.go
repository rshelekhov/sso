package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func passwordHashBcrypt(password string, p PasswordHashBcryptParams, pepper []byte) (string, error) {
	const method = "service.token.PasswordHashBcrypt"

	passwordHmac := hmac.New(sha256.New, pepper)
	_, err := passwordHmac.Write([]byte(password))
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	passwordBcrypt, err := bcrypt.GenerateFromPassword(passwordHmac.Sum(nil), p.Cost)
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	return string(passwordBcrypt), nil
}

func passwordMatchBcrypt(hash, password string, pepper []byte) (bool, error) {
	const method = "service.token.PasswordMatchBcrypt"

	passwordHmac := hmac.New(sha256.New, pepper)
	_, err := passwordHmac.Write([]byte(password))
	if err != nil {
		return false, fmt.Errorf("%s: %w", method, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), passwordHmac.Sum(nil))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", method, err)
	}

	return true, nil
}
