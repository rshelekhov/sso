package auth

import (
	"context"

	"github.com/rshelekhov/sso/internal/config"
	"google.golang.org/grpc"
)

func UnaryServerInterceptor(cfg *config.GRPCMethodsConfig, jwtInterceptor grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		methodConfigs := cfg.GetMethodConfigs()
		if methodConfig, exists := methodConfigs[info.FullMethod]; exists && methodConfig.RequireJWT {
			return jwtInterceptor(ctx, req, info, handler)
		}
		return handler(ctx, req)
	}
}
