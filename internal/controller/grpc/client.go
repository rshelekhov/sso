package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/lib/e"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
)

func (c *gRPCController) RegisterApp(ctx context.Context, req *ssov1.RegisterAppRequest) (*ssov1.RegisterAppResponse, error) {
	const method = "controller.gRPC.RegisterApp"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateRegisterAppRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	// TODO: change to GetClientName after updating imports of sso-protos
	clientName := req.GetAppName()

	err = c.clientUsecase.RegisterClient(ctx, clientName)
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.RegisterAppResponse{}, nil
}
