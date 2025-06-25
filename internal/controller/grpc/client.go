package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/lib/e"

	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
)

func (c *gRPCController) RegisterClient(ctx context.Context, req *clientv1.RegisterClientRequest) (*clientv1.RegisterClientResponse, error) {
	const method = "controller.gRPC.RegisterClient"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateRegisterClientRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	clientName := req.GetClientName()

	err = c.clientUsecase.RegisterClient(ctx, clientName)
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &clientv1.RegisterClientResponse{}, nil
}
