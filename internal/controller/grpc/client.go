package grpc

import (
	"context"

	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
)

func (c *gRPCController) RegisterClient(ctx context.Context, req *clientv1.RegisterClientRequest) (*clientv1.RegisterClientResponse, error) {
	const method = "controller.gRPC.RegisterClient"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateRegisterClientRequest(r.(*clientv1.RegisterClientRequest))
	}); err != nil {
		return nil, err
	}

	clientName := req.GetClientName()

	err = c.clientUsecase.RegisterClient(ctx, clientName)
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &clientv1.RegisterClientResponse{}, nil
}
