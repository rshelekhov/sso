package token

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/segmentio/ksuid"
	"time"
)

type JWTManager interface {
	NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error)
	NewRefreshToken() string
	Issuer() string
	AccessTokenTTL() time.Duration
	RefreshTokenTTL() time.Duration
	JWKSTTL() time.Duration
	Kid(appID string) (string, error)
	RefreshTokenCookieDomain() string
	RefreshTokenCookiePath() string
	SigningMethod() string
}

func (s *service) NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error) {
	const method = "service.token.NewAccessToken"

	if appID == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrAppIDIsNotAllowed)
	}

	if kid == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrEmptyKidIsNotAllowed)
	}

	claims := jwt.MapClaims{}

	if additionalClaims != nil { // nolint:gosimple
		for k, v := range additionalClaims {
			claims[k] = v
		}
	}

	privateKeyPEM, err := s.keyStorage.GetPrivateKey(appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetPrivateKey, err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToParsePrivateKey, err)
	}

	token := jwt.NewWithClaims(s.algorithm(), claims)

	token.Header["kid"] = kid

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToSignToken, err)
	}

	return signedToken, nil
}

func (s *service) NewRefreshToken() string {
	return ksuid.New().String()
}

func (s *service) Issuer() string {
	return s.issuer
}

func (s *service) AccessTokenTTL() time.Duration {
	return s.accessTokenTTL
}

func (s *service) RefreshTokenTTL() time.Duration {
	return s.refreshTokenTTL
}

func (s *service) JWKSTTL() time.Duration {
	return s.jwksTTL
}

func (s *service) Kid(appID string) (string, error) {
	const method = "service.service.Kid"

	if appID == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrAppIDIsNotAllowed)
	}

	// Get public key
	pub, err := s.PublicKey(appID)
	if err != nil {
		return "", err
	}

	// Create key ID
	var keyID string
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		s := sha1.Sum(der)
		keyID = base64.URLEncoding.EncodeToString(s[:])
	}

	return keyID, nil
}

func (s *service) RefreshTokenCookieDomain() string {
	return s.refreshTokenCookieDomain
}

func (s *service) RefreshTokenCookiePath() string {
	return s.refreshTokenCookiePath
}

func (s *service) SigningMethod() string {
	return string(s.signingMethod)
}

func (s *service) algorithm() jwt.SigningMethod {
	switch s.signingMethod {
	case SigningMethodRS256:
		return jwt.SigningMethodRS256
	case SigningMethodES256:
		return jwt.SigningMethodES256
	default:
		return jwt.SigningMethodRS256
	}
}
