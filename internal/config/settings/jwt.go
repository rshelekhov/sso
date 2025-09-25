package settings

import (
	"fmt"
	"time"

	"github.com/rshelekhov/sso/internal/domain/service/token"
)

type JWT struct {
	Issuer                   string            `yaml:"Issuer" default:"sso"`
	SigningMethod            SigningMethodType `yaml:"SigningMethod" default:"RS256"`
	JWKSTTL                  time.Duration     `yaml:"JWKSTTL" default:"24h"`
	AccessTokenTTL           time.Duration     `yaml:"AccessTokenTTL" default:"15m"`
	RefreshTokenTTL          time.Duration     `yaml:"RefreshTokenTTL" default:"720h"`
	RefreshTokenCookieDomain string            `yaml:"RefreshTokenCookieDomain"`
	RefreshTokenCookiePath   string            `yaml:"RefreshTokenCookiePath"`
}

type SigningMethodType string

const (
	SigningMethodES256 SigningMethodType = "ES256"
	SigningMethodRS256 SigningMethodType = "RS256"
)

func ToJWTConfig(jwt JWT) (token.JWT, error) {
	const op = "settings.JWT.ToJWTConfig"

	signingMethod, err := validateAndConvertSigningMethod(jwt.SigningMethod)
	if err != nil {
		return token.JWT{}, fmt.Errorf("%s: %w", op, err)
	}

	return token.JWT{
		Issuer:                   jwt.Issuer,
		SigningMethod:            signingMethod,
		JWKSTTL:                  jwt.JWKSTTL,
		AccessTokenTTL:           jwt.AccessTokenTTL,
		RefreshTokenTTL:          jwt.RefreshTokenTTL,
		RefreshTokenCookieDomain: jwt.RefreshTokenCookieDomain,
		RefreshTokenCookiePath:   jwt.RefreshTokenCookiePath,
	}, nil
}

func validateAndConvertSigningMethod(method SigningMethodType) (token.SigningMethodType, error) {
	switch method {
	case SigningMethodES256:
		return token.SigningMethodES256, nil
	case SigningMethodRS256:
		return token.SigningMethodRS256, nil
	case "":
		return "", fmt.Errorf("jwt signing method is empty")
	default:
		return "", fmt.Errorf("unknown jwt signing method: %s", method)
	}
}
