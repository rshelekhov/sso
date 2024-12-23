package token

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"strings"
)

func (s *Service) ExtractUserIDFromContext(ctx context.Context, appID string) (string, error) {
	const method = "Service.token.ExtractUserIDFromContext"

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

func (s *Service) getClaimsFromToken(ctx context.Context, appID string) (map[string]interface{}, error) {
	const method = "Service.token.getClaimsFromToken"

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

func (s *Service) getTokenFromContext(ctx context.Context, appID string) (*jwt.Token, error) {
	const method = "Service.token.getTokenFromContext"

	token, ok := ctx.Value(domain.AccessTokenKey).(string)
	if !ok {
		return nil, fmt.Errorf("%s: %w", method, domain.ErrNoTokenFoundInContext)
	}

	return s.parseToken(token, appID)
}

func (s *Service) parseToken(tokenRaw, appID string) (*jwt.Token, error) {
	const method = "Service.token.parseToken"

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
