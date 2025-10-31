package jwtauth

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// HTTPMiddleware is a HTTP middleware handler that verifies a JWT token from an HTTP request.
//
// HTTPMiddleware will search for a JWT token in a http request in order:
// 1. 'Authorization: BEARER T' request header
// 2. Cookie 'access_token' value
//
// The middleware parses the token, verifies it, and stores both the token string and
// parsed claims in the context for downstream handlers to use.
func (m *manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, err := m.getClientIDFromHTTPRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, claims, err := m.findVerifyAndParseClaims(r, clientID, m.ExtractTokenFromHTTP, m.ExtractTokenFromCookies)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = m.ToContext(ctx, token)
		ctx = ClaimsToContext(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getClientIDFromHTTPRequest returns the clientID from the manager struct or from the http request
func (m *manager) getClientIDFromHTTPRequest(r *http.Request) (string, error) {
	if m.clientID != "" {
		return m.clientID, nil
	}

	clientID := r.Header.Get(ClientIDHeader)
	if clientID == "" {
		return "", ErrClientIDHeaderNotFoundInHTTPRequest
	}

	return clientID, nil
}

// findVerifyAndParseClaims searches for a JWT token, verifies it, and extracts claims.
// Returns the token string, parsed claims, or an error if validation fails.
func (m *manager) findVerifyAndParseClaims(
	r *http.Request,
	clientID string,
	findTokenFns ...func(r *http.Request) (string, error),
) (string, *Claims, error) {
	tokenString, err := m.findAndVerifyToken(r, clientID, findTokenFns...)
	if err != nil {
		return "", nil, err
	}

	// Parse and verify token in one go
	parsedToken, err := m.ParseToken(clientID, tokenString)
	if err != nil {
		return "", nil, Errors(err)
	}

	if !parsedToken.Valid {
		return "", nil, ErrInvalidToken
	}

	// Extract claims
	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, ErrFailedToParseTokenClaims
	}

	claims := FromMapClaims(mapClaims)

	return tokenString, claims, nil
}

// findAndVerifyToken searches for a JWT token using the provided search functions (header and cookie).
// Returns the found token string or an error if no valid token is found.
func (m *manager) findAndVerifyToken(
	r *http.Request,
	clientID string,
	findTokenFns ...func(r *http.Request) (string, error),
) (string, error) {
	var tokenString string

	for _, fn := range findTokenFns {
		tokenString, _ = fn(r)
		if tokenString != "" {
			break
		}
	}

	if tokenString == "" {
		return "", ErrTokenNotFound
	}

	if err := m.verifyToken(clientID, tokenString); err != nil {
		return "", err
	}

	return tokenString, nil
}
