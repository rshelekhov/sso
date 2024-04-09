package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func PasswordHashBcrypt(password string, cost int, salt []byte) (string, error) {
	const method = "jwt.PasswordHashBcrypt"

	if password == "" {
		return "", fmt.Errorf("%s: password is empty", method)
	}
	if len(salt) == 0 {
		return "", fmt.Errorf("%s: salt is empty", method)
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
	const method = "jwt.PasswordMatch"

	if hash == "" {
		return false, fmt.Errorf("%s: hash is empty", method)
	} else if password == "" {
		return false, fmt.Errorf("%s: password is empty", method)
	} else if len(salt) == 0 {
		return false, fmt.Errorf("%s: salt is empty", method)
	}

	passwordHmac := hmac.New(sha256.New, salt)
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
