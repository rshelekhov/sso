package service

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/segmentio/ksuid"
	"time"
)

type ContextKey struct {
	name string
}

var TokenCtxKey = ContextKey{"Token"}

type TokenService struct {
	SigningMethod            jwt.SigningMethod
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	RefreshTokenCookieDomain string
	RefreshTokenCookiePath   string
	PasswordHashCost         int
	PasswordHashSalt         string
}

func NewJWTokenService(
	signingMethod jwt.SigningMethod,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshTokenCookieDomain string,
	refreshTokenCookiePath string,
	passwordHashCost int,
	passwordHashSalt string,
) *TokenService {
	return &TokenService{
		SigningMethod:            signingMethod,
		AccessTokenTTL:           accessTokenTTL,
		RefreshTokenTTL:          refreshTokenTTL,
		RefreshTokenCookieDomain: refreshTokenCookieDomain,
		RefreshTokenCookiePath:   refreshTokenCookiePath,
		PasswordHashCost:         passwordHashCost,
		PasswordHashSalt:         passwordHashSalt,
	}
}

func (j *TokenService) NewAccessToken(additionalClaims map[string]interface{}, signKey string) (string, error) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(j.AccessTokenTTL).Unix(),
	}

	if additionalClaims != nil { // nolint:gosimple
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(j.SigningMethod, claims)

	return token.SignedString([]byte(signKey))
}

func (j *TokenService) NewRefreshToken() (string, error) {
	token := ksuid.New().String()
	return token, nil
}

func GetTokenFromContext(ctx context.Context) (*jwt.Token, error) {
	token, ok := ctx.Value(TokenCtxKey).(*jwt.Token)
	if !ok {
		return nil, le.ErrNoTokenFoundInCtx
	}

	return token, nil
}

func GetClaimsFromToken(ctx context.Context) (map[string]interface{}, error) {
	token, err := GetTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, le.ErrFailedToParseTokenClaims
	}

	return claims, nil
}

func GetUserID(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromToken(ctx)
	if err != nil {
		return "", err
	}

	userID, ok := claims[key.ContextUserID]
	if !ok {
		return "", le.ErrUserIDNotFoundInCtx
	}

	return userID.(string), nil
}
