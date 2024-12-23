package grpc

import (
	"context"
	"errors"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/src/lib/constant/le"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (c *controller) RegisterApp(ctx context.Context, req *ssov1.RegisterAppRequest) (*ssov1.RegisterAppResponse, error) {
	if err := validateRegisterAppRequest(req); err != nil {
		return nil, err
	}

	appName := req.GetAppName()

	err := c.appUsecase.RegisterApp(ctx, appName)

	switch {
	case errors.Is(err, le.ErrAppAlreadyExists):
		return nil, status.Error(codes.AlreadyExists, le.ErrAppAlreadyExists.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	return &ssov1.RegisterAppResponse{}, nil
}
