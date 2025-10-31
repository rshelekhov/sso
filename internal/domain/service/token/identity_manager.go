package token

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
)

func (s *Service) ExtractUserIDFromTokenInContext(ctx context.Context, clientID string) (string, error) {
	const method = "service.token.ExtractUserIDFromTokenInContext"

	claims, err := s.getClaimsFromToken(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}

	// Debug logging
	fmt.Printf("DEBUG: ExtractUserIDFromTokenInContext - claims: %+v\n", claims)
	fmt.Printf("DEBUG: Looking for UserIDKey '%s' in claims\n", domain.UserIDKey)

	userID, ok := claims[domain.UserIDKey]
	if !ok {
		return "", fmt.Errorf("%s: %w", method, domain.ErrUserIDNotFoundInContext)
	}

	return userID.(string), nil
}

func (s *Service) getClaimsFromToken(ctx context.Context, clientID string) (map[string]interface{}, error) {
	const method = "service.token.getClaimsFromToken"

	fmt.Printf("DEBUG: getClaimsFromToken called with clientID: %s\n", clientID)

	token, err := s.getTokenFromContext(ctx, clientID)
	if err != nil {
		fmt.Printf("DEBUG: getTokenFromContext failed: %v\n", err)
		return nil, fmt.Errorf("%s: %w", method, err)
	}

	fmt.Printf("DEBUG: token valid: %t\n", token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Printf("DEBUG: failed to cast token.Claims to jwt.MapClaims\n")
		return nil, fmt.Errorf("%s: %w", method, domain.ErrFailedToParseTokenClaims)
	}

	fmt.Printf("DEBUG: claims successfully extracted: %+v\n", claims)
	return claims, nil
}

func (s *Service) getTokenFromContext(ctx context.Context, clientID string) (*jwt.Token, error) {
	const method = "service.token.getTokenFromContext"

	token, ok := ctx.Value(domain.TokenCtxKey).(string)
	if !ok {
		return nil, fmt.Errorf("%s: %w", method, domain.ErrNoTokenFoundInContext)
	}

	return s.parseToken(token, clientID)
}

func (s *Service) parseToken(tokenRaw, clientID string) (*jwt.Token, error) {
	const method = "service.token.parseToken"

	tokenString := strings.TrimSpace(tokenRaw)

	//nolint:revive
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		return s.PublicKey(clientID)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %w", method, domain.ErrFailedToParseTokenWithClaims, err)
	}

	return token, nil
}
