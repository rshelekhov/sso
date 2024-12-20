package token

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"strings"
)

type IdentityManager interface {
	ExtractUserIDFromContext(ctx context.Context, appID string) (string, error)
}

func (s *service) ExtractUserIDFromContext(ctx context.Context, appID string) (string, error) {
	const method = "service.token.ExtractUserIDFromContext"

	claims, err := s.getClaimsFromToken(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	userID, ok := claims[domain.UserIDKey]
	if !ok {
		return "", fmt.Errorf("%s: %w", method, domain.ErrUserIDNotFoundInContext)
	}

	return userID.(string), nil
}

func (s *service) getClaimsFromToken(ctx context.Context, appID string) (map[string]interface{}, error) {
	const method = "service.token.getClaimsFromToken"

	token, err := s.getTokenFromContext(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%s: %w", method, domain.ErrFailedToParseTokenClaims)
	}

	return claims, nil
}

func (s *service) getTokenFromContext(ctx context.Context, appID string) (*jwt.Token, error) {
	const method = "service.token.getTokenFromContext"

	token, ok := ctx.Value(domain.AccessTokenKey).(string)
	if !ok {
		return nil, fmt.Errorf("%s: %w", method, domain.ErrNoTokenFoundInContext)
	}

	return s.parseToken(token, appID)
}

func (s *service) parseToken(tokenRaw, appID string) (*jwt.Token, error) {
	const method = "service.token.parseToken"

	tokenString := strings.TrimSpace(tokenRaw)

	//nolint:revive
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.PublicKey(appID)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToParseTokenWithClaims, err)
	}

	return token, nil
}
