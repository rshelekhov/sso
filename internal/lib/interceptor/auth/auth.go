package auth

import (
	"context"

	"github.com/rshelekhov/sso/internal/config/grpcmethods"
	"google.golang.org/grpc"
)

func UnaryServerInterceptor(cfg *grpcmethods.Methods, jwtInterceptor grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check token and place it to context
		if cfg.IsTokenRequired(info.FullMethod) {
			return jwtInterceptor(ctx, req, info, handler)
		}

		// Continue without token
		return handler(ctx, req)
	}
}
