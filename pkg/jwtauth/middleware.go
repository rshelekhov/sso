package jwtauth

import (
	"context"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor is an interceptor that verifies a JWT token from gRPC metadata.
//
// UnaryServerInterceptor will extract a JWT token from gRPC metadata using the authorization key.
func (m *manager) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		appID, err := m.getAppIDFromGRPCMetadata(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		token, err := m.ExtractTokenFromGRPC(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		if token == "" {
			return "", status.Error(codes.Unauthenticated, ErrTokenNotFound.Error())
		}

		if err := m.verifyToken(appID, token); err != nil {
			return "", status.Error(codes.Unauthenticated, err.Error())
		}

		ctx = context.WithValue(ctx, AuthorizationHeader, token)

		return handler(ctx, req)
	}
}

// HTTPMiddleware is a HTTP middleware handler that verifies a JWT token from an HTTP request.
//
// HTTPMiddleware will search for a JWT token in a http request in order:
// 1. 'Authorization: BEARER T' request header
// 2. Cookie 'access_token' value
//
// The HTTPMiddleware always calls the next http handler in sequence.
func (m *manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appID, err := m.getAppIDFromHTTPRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := m.findAndVerifyToken(r, appID, m.ExtractTokenFromHTTP, m.ExtractTokenFromCookies)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), AuthorizationHeader, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getAppIDFromGRPCMetadata returns the appID from the manager struct or from gRPC metadata
func (m *manager) getAppIDFromGRPCMetadata(ctx context.Context) (string, error) {
	if m.appID != "" {
		return m.appID, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoGRPCMetadata
	}

	values := md.Get(AppIDHeader)
	if len(values) == 0 {
		return "", ErrAppIDHeaderNotFoundInGRPCMetadata
	}

	return values[0], nil
}

// getAppIDFromHTTPRequest returns the appID from the manager struct or from the http request
func (m *manager) getAppIDFromHTTPRequest(r *http.Request) (string, error) {
	if m.appID != "" {
		return m.appID, nil
	}

	appID := r.Header.Get(AppIDHeader)
	if appID == "" {
		return "", ErrAppIDHeaderNotFoundInHTTPRequest
	}

	return appID, nil
}

// findAndVerifyToken searches for a JWT token using the provided search functions (header and cookie).
// Returns the found token string or an error if no valid token is found.
func (m *manager) findAndVerifyToken(
	r *http.Request,
	appID string,
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

	if err := m.verifyToken(appID, tokenString); err != nil {
		return "", err
	}

	return tokenString, nil
}
