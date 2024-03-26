package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func PasswordHashBcrypt(password string, cost int, salt []byte) (string, error) {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}

	passwordHmac := hmac.New(sha256.New, salt)
	_, err := passwordHmac.Write([]byte(password))
	if err != nil {
		return "", err
	}

	passwordBcrypt, err := bcrypt.GenerateFromPassword(passwordHmac.Sum(nil), cost)
	if err != nil {
		return "", err
	}

	return string(passwordBcrypt), nil
}

func PasswordMatch(hash, password string, salt []byte) (bool, error) {
	passwordHmac := hmac.New(sha256.New, salt)
	_, err := passwordHmac.Write([]byte(password))
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), passwordHmac.Sum(nil))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return true, nil
}
