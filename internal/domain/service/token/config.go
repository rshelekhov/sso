package token

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	JWT
	PasswordHashParams
}

type JWT struct {
	Issuer                   string
	SigningMethod            SigningMethodType
	JWKSTTL                  time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	RefreshTokenCookieDomain string
	RefreshTokenCookiePath   string
}

type SigningMethodType string

const (
	SigningMethodES256 SigningMethodType = "ES256"
	SigningMethodRS256 SigningMethodType = "RS256"
)

type PasswordHashType string

const (
	PasswordHashDefault PasswordHashType = "default"
	PasswordHashArgon2  PasswordHashType = "argon2"
	PasswordHashBcrypt  PasswordHashType = "bcrypt"
)

type PasswordHashParams struct {
	Type       PasswordHashType
	SaltLength uint32
	Pepper     string
	Argon      *PasswordHashArgon2Params
	Bcrypt     *PasswordHashBcryptParams
}

type PasswordHashArgon2Params struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	KeyLength   uint32
}

type PasswordHashBcryptParams struct {
	Cost int
}

var (
	defaultPasswordHashParams = PasswordHashParams{
		Type:       PasswordHashDefault,
		SaltLength: 32,
		Pepper:     "red-hot-chili-peppers",
		Argon:      &defaultPasswordHashArgon2Params,
	}

	defaultPasswordHashArgon2Params = PasswordHashArgon2Params{
		Time:        2,
		Memory:      32 * 1024,
		Parallelism: 2,
		KeyLength:   32,
	}

	//nolint:unused // This variable will be used in the future
	defaultPasswordHashBcryptParams = PasswordHashBcryptParams{
		Cost: bcrypt.DefaultCost,
	}
)
