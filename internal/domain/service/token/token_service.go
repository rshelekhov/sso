package token

import (
	"time"
)

type (
	Service interface {
		JWTManager
		PasswordManager
		IdentityManager
		KeyManager
	}

	KeyStorage interface {
		SavePrivateKey(appID string, privateKeyPEM []byte) error
		GetPrivateKey(appID string) ([]byte, error)
	}
)

type service struct {
	issuer                   string
	signingMethod            SigningMethodType
	passwordHashParams       PasswordHashParams
	jwksTTL                  time.Duration
	accessTokenTTL           time.Duration
	refreshTokenTTL          time.Duration
	refreshTokenCookieDomain string
	refreshTokenCookiePath   string
	keyStorage               KeyStorage
}

func NewService(cfg Config, storage KeyStorage) Service {
	return &service{
		issuer:                   cfg.Issuer,
		signingMethod:            cfg.SigningMethod,
		passwordHashParams:       cfg.PasswordHashParams,
		jwksTTL:                  cfg.JWKSTTL,
		accessTokenTTL:           cfg.AccessTokenTTL,
		refreshTokenTTL:          cfg.RefreshTokenTTL,
		refreshTokenCookieDomain: cfg.RefreshTokenCookieDomain,
		refreshTokenCookiePath:   cfg.RefreshTokenCookiePath,
		keyStorage:               storage,
	}
}
