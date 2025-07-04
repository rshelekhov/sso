package clientid

import (
	"context"
	"fmt"

	"github.com/rshelekhov/sso/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Interceptor struct {
	cfg *config.GRPCMethodsConfig
}

func NewInterceptor(cfg *config.GRPCMethodsConfig) *Interceptor {
	return &Interceptor{
		cfg: cfg,
	}
}

const (
	Header = "X-Client-ID"
	CtxKey = "ClientID"
)

func (i *Interceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		methodConfigs := i.cfg.GetMethodConfigs()
		if methodConfig, exists := methodConfigs[info.FullMethod]; exists && methodConfig.RequireClientID {
			clientID, err := extractFromGRPC(ctx)
			if err != nil {
				return nil, err
			}

			ctx = toContext(ctx, clientID)

			return handler(ctx, req)
		}
		return handler(ctx, req)
	}
}

func FromContext(ctx context.Context) (string, bool) {
	clientID, ok := ctx.Value(CtxKey).(string)
	return clientID, ok
}

func extractFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no gRPC metadata")
	}

	values := md.Get(Header)
	if len(values) == 0 {
		return "", fmt.Errorf("clientID not found in gRPC metadata")
	}

	return values[0], nil
}

func toContext(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, CtxKey, clientID)
}
