package settings

import "time"

type JWT struct {
	Issuer                   string        `mapstructure:"JWT_ISSUER"`
	SigningMethod            string        `mapstructure:"JWT_SIGNING_METHOD"`
	JWKSetTTL                time.Duration `mapstructure:"JWT_JWK_SET_TTL"`
	AccessTokenTTL           time.Duration `mapstructure:"JWT_ACCESS_TOKEN_TTL"`
	RefreshTokenTTL          time.Duration `mapstructure:"JWT_REFRESH_TOKEN_TTL"`
	RefreshTokenCookieDomain string        `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_DOMAIN"`
	RefreshTokenCookiePath   string        `mapstructure:"JWT_REFRESH_TOKEN_COOKIE_PATH"`
}
