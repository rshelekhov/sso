package requestid

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const requestIDKey = "requestIDKey"

func UnaryServerInterceptor(opt ...Option) grpc.UnaryServerInterceptor {
	var opts options
	opts.validator = defaultRequestIDValidator
	for _, o := range opt {
		o.apply(&opts)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID := HandleRequestID(ctx, opts.validator)

		ctx = context.WithValue(ctx, requestIDKey, requestID)
		return handler(ctx, req)
	}
}

func FromContext(ctx context.Context) string {
	requestID, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return ""
	}
	return requestID
}
