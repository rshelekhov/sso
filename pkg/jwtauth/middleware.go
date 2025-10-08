package jwtauth

import (
	"context"
	"net/http"
)

// HTTPMiddleware is a HTTP middleware handler that verifies a JWT token from an HTTP request.
//
// HTTPMiddleware will search for a JWT token in a http request in order:
// 1. 'Authorization: BEARER T' request header
// 2. Cookie 'access_token' value
//
// The HTTPMiddleware always calls the next http handler in sequence.
func (m *manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, err := m.getClientIDFromHTTPRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := m.findAndVerifyToken(r, clientID, m.ExtractTokenFromHTTP, m.ExtractTokenFromCookies)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), AuthorizationHeader, token)
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
