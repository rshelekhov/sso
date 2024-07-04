package requestid

import (
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/segmentio/ksuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

func handleRequestID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return newRequestID()
	}

	requestID := md.Get(key.RequestID)
	if requestID == nil {
		return newRequestID()
	}

	return requestID[0]
}

func newRequestID() string {
	return ksuid.New().String()
}
