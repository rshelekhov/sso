package token

import (
	"crypto/rand"
	"fmt"
	"github.com/rshelekhov/sso/internal/domain"
	"io"
)

type PasswordManager interface {
	HashPassword(password string) (string, error)
	PasswordMatch(hash, password string) (bool, error)
}

func (s *service) HashPassword(password string) (string, error) {
	const method = "service.token.HashPassword"

	if password == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrPasswordIsNotAllowed)
	}

	params := s.passwordHashParams

	if s.passwordHashParams.Type == PasswordHashDefault {
		params = defaultPasswordHashParams
	}

	salt, err := generateSalt(params.SaltLength)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGenerateSalt, err)
	}

	var hash string

	switch params.Type {
	case PasswordHashDefault, PasswordHashArgon2:
		hash = passwordHashArgon2(password, *params.Argon, salt, []byte(params.Pepper))
	case PasswordHashBcrypt:
		hash, err = passwordHashBcrypt(password, *params.Bcrypt, []byte(params.Pepper))
	default:
		return "", fmt.Errorf("%s: %w", method, domain.ErrUnsupportedPasswordHashType)
	}

	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToHashPassword, err)
	}

	return hash, nil
}

func (s *service) PasswordMatch(hash, password string) (bool, error) {
	const method = "service.token.PasswordMatch"

	if hash == "" {
		return false, fmt.Errorf("%s: %w", method, domain.ErrHashIsNotAllowed)
	}

	if password == "" {
		return false, fmt.Errorf("%s: %w", method, domain.ErrPasswordIsNotAllowed)
	}

	switch s.passwordHashParams.Type {
	case PasswordHashDefault, PasswordHashArgon2:
		return passwordMatchArgon2(hash, password, []byte(s.passwordHashParams.Pepper))
	case PasswordHashBcrypt:
		return passwordMatchBcrypt(hash, password, []byte(s.passwordHashParams.Pepper))
	default:
		return false, fmt.Errorf("%s: %w", method, domain.ErrUnsupportedPasswordHashType)
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
