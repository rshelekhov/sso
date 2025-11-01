package jwtauth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor is an interceptor that verifies a JWT token from gRPC metadata.
//
// UnaryServerInterceptor will extract a JWT token from gRPC metadata using the authorization key,
// verify it, parse claims, and add both token and claims to the context.
func (m *manager) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		clientID, err := m.getClientIDFromGRPCMetadata(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		token, err := m.ExtractTokenFromGRPC(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		if token == "" {
			return nil, status.Error(codes.Unauthenticated, ErrTokenNotFound.Error())
		}

		// Parse and verify token
		parsedToken, err := m.ParseToken(clientID, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, Errors(err).Error())
		}

		if !parsedToken.Valid {
			return nil, status.Error(codes.Unauthenticated, ErrInvalidToken.Error())
		}

		// Extract claims
		mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, ErrFailedToParseTokenClaims.Error())
		}

		claims := FromMapClaims(mapClaims)

		// Add token and claims to context
		ctx = m.ToContext(ctx, token)
		ctx = ClaimsToContext(ctx, claims)

		return handler(ctx, req)
	}
}

// AuthUnaryClientInterceptor automatically adds authorization token and client ID to outgoing gRPC metadata
// It extracts the token from context.Value (set by HTTP middleware) and adds it to gRPC metadata
func (m *manager) AuthUnaryClientInterceptor(clientID string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Always add client ID
		md := metadata.Pairs(ClientIDHeader, clientID)

		// Try to extract authorization token from context
		if token, ok := ctx.Value(TokenCtxKey).(string); ok && token != "" {
			// Add authorization token to metadata
			md.Set(AuthorizationHeader, token)
		}

		// Add metadata to outgoing context
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Proceed with the call
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// getClientIDFromGRPCMetadata returns the clientID from the manager struct or from gRPC metadata
func (m *manager) getClientIDFromGRPCMetadata(ctx context.Context) (string, error) {
	if m.clientID != "" {
		return m.clientID, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoGRPCMetadata
	}

	values := md.Get(ClientIDHeader)
	if len(values) == 0 {
		return "", ErrClientIDHeaderNotFoundInGRPCMetadata
	}

	return values[0], nil
}
