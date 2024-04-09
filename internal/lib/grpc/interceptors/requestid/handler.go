package requestid

import (
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func UnaryServerInterceptor() grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID := handleRequestID(ctx)

		ctx = context.WithValue(ctx, key.RequestID, requestID)
		return handler(ctx, req)
	}
}

func FromContext(ctx context.Context) (string, error) {
	requestID, ok := ctx.Value(key.RequestID).(string)
	if !ok {
		return "", le.ErrRequestIDNotFoundInCtx
	}
	return requestID, nil
}
