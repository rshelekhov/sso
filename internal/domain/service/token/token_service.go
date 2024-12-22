package token

import (
	"time"
)

type Service struct {
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

type KeyStorage interface {
	SavePrivateKey(appID string, privateKeyPEM []byte) error
	GetPrivateKey(appID string) ([]byte, error)
}

func NewService(cfg Config, storage KeyStorage) *Service {
	return &Service{
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
