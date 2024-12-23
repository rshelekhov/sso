package settings

import (
	"fmt"
	"github.com/rshelekhov/sso/src/domain/service/token"
	"time"
)

type JWT struct {
	Issuer                   string            `mapstructure:"JWT_ISSUER" envDefault:"sso"`
	SigningMethod            SigningMethodType `mapstructure:"JWT_SIGNING_METHOD" envDefault:"RS256"`
	JWKSURL                  string            `mapstructure:"JWT_JWKS_URL"`
	JWKSTTL                  time.Duration     `mapstructure:"JWT_JWKS_TTL" envDefault:"24h"`
	AccessTokenTTL           time.Duration     `mapstructure:"JWT_ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL          time.Duration     `mapstructure:"JWT_REFRESH_TOKEN_TTL" envDefault:"720h"`
	RefreshTokenCookieDomain string            `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_DOMAIN"`
	RefreshTokenCookiePath   string            `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_PATH"`
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
		return token.SigningMethodES256, nil
	case "":
		return "", fmt.Errorf("jwt signing method is empty")
	default:
		return "", fmt.Errorf("unknown jwt signing method: %s", method)
	}
}
