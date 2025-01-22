package auth

import (
	"context"
	"github.com/rshelekhov/sso/internal/config/grpcmethods"
	"google.golang.org/grpc"
)

func UnaryServerInterceptor(cfg *grpcmethods.Methods, jwtMiddleware grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for public methods
		if cfg.IsPublic(info.FullMethod) {
			return handler(ctx, req)
		}

		// Check token and place it to context
		return jwtMiddleware(ctx, req, info, handler)
	}
}
