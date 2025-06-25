package token

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"maps"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/segmentio/ksuid"
)

func (s *Service) NewAccessToken(clientID, kid string, additionalClaims map[string]any) (string, error) {
	const method = "service.token.NewAccessToken"

	if clientID == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrClientIDIsNotAllowed)
	}

	if kid == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrEmptyKidIsNotAllowed)
	}

	claims := jwt.MapClaims{}

	if additionalClaims != nil {
		maps.Copy(claims, additionalClaims)
	}

	privateKeyPEM, err := s.keyStorage.GetPrivateKey(clientID)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetPrivateKey, err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToParsePrivateKey, err)
	}

	token := jwt.NewWithClaims(s.algorithm(), claims)

	token.Header[domain.KIDKey] = kid

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToSignToken, err)
	}

	return signedToken, nil
}

func (s *Service) NewRefreshToken() string {
	return ksuid.New().String()
}

func (s *Service) Issuer() string {
	return s.issuer
}

func (s *Service) AccessTokenTTL() time.Duration {
	return s.accessTokenTTL
}

func (s *Service) RefreshTokenTTL() time.Duration {
	return s.refreshTokenTTL
}

func (s *Service) JWKSTTL() time.Duration {
	return s.jwksTTL
}

func (s *Service) Kid(clientID string) (string, error) {
	const method = "service.Service.Kid"

	if clientID == "" {
		return "", fmt.Errorf("%s: %w", method, domain.ErrClientIDIsNotAllowed)
	}

	// Get public key
	pub, err := s.PublicKey(clientID)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToGetPublicKey, err)
	}

	// Create key ID
	var kid string
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		s := sha1.Sum(der)
		kid = base64.URLEncoding.EncodeToString(s[:])
	}

	return kid, nil
}

func (s *Service) RefreshTokenCookieDomain() string {
	return s.refreshTokenCookieDomain
}

func (s *Service) RefreshTokenCookiePath() string {
	return s.refreshTokenCookiePath
}

func (s *Service) SigningMethod() string {
	return string(s.signingMethod)
}

func (s *Service) algorithm() jwt.SigningMethod {
	switch s.signingMethod {
	case SigningMethodRS256:
		return jwt.SigningMethodRS256
	case SigningMethodES256:
		return jwt.SigningMethodES256
	default:
		return jwt.SigningMethodRS256
	}
}
