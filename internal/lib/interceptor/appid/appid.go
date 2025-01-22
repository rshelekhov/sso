package appid

import (
	"context"
	"github.com/rshelekhov/sso/internal/config/grpcmethods"
	"google.golang.org/grpc"
)

func UnaryServerInterceptor(cfg *grpcmethods.Methods, appIDInterceptor grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check appID and place it to context
		if cfg.IsAppIDRequired(info.FullMethod) {
			return appIDInterceptor(ctx, req, info, handler)
		}

		// Continue without appID
		return handler(ctx, req)
	}
}
