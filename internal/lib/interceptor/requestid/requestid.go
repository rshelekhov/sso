package requestid

import (
	"context"

	"github.com/segmentio/ksuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Interceptor struct{}

func NewInterceptor() *Interceptor {
	return &Interceptor{}
}

const (
	Header = "X-Request-ID"
	CtxKey = "RequestID"
)

func (i *Interceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID := extractFromGRPC(ctx)
		ctx = toContext(ctx, requestID)

		return handler(ctx, req)
	}
}

func FromContext(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(CtxKey).(string)
	return requestID, ok
}

func extractFromGRPC(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return newID()
	}

	values := md.Get(Header)
	if len(values) == 0 {
		return newID()
	}

	return values[0]
}

func toContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, CtxKey, requestID)
}

func newID() string {
	return ksuid.New().String()
}
