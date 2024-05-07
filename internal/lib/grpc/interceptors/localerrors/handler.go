package localerrors

import (
	"context"
	"errors"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func UnaryServerInterceptor() grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err != nil {
			if errors.Is(err, le.ErrAppIDDoesNotExist) {
				return nil, status.Error(codes.Unauthenticated, le.ErrAppIDDoesNotExist.Error())
			}
		}
		return resp, err
	}
}
