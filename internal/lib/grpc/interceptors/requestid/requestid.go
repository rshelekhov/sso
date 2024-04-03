package requestid

import (
	"github.com/google/uuid"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
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
	return uuid.New().String()
}
