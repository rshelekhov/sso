package grpc

import (
	"context"
	"fmt"
	"log/slog"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (c *gRPCController) GetUserRole(ctx context.Context, req *ssov1.GetUserRoleRequest) (*ssov1.GetUserRoleResponse, error) {
	const method = "controller.gRPC.GetUserRole"

	log := c.log.With(
		slog.String("method", method),
		slog.String("targetUserID", req.UserId),
	)

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(controller.ErrFailedToGetRequestID)
	}

	log = log.With(slog.String("requestID", reqID))

	err = validateGetUserRoleRequest(req)
	if err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(controller.ErrFailedToGetAndValidateAppID)
	}

	role, err := c.userUsecase.GetUserRole(ctx, appID, req.UserId)
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.GetUserRoleResponse{
		Role: role,
	}, nil
}

func (c *gRPCController) ChangeUserRole(ctx context.Context, req *ssov1.ChangeUserRoleRequest) (*ssov1.ChangeUserRoleResponse, error) {
	const method = "controller.gRPC.ChangeUserRole"

	log := c.log.With(
		slog.String("method", method),
		slog.String("targetUserID", req.UserId),
		slog.String("newRole", req.Role),
	)

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(controller.ErrFailedToGetRequestID)
	}

	log = log.With(slog.String("requestID", reqID))

	if err := validateChangeUserRoleRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(controller.ErrFailedToGetAndValidateAppID)
	}

	if err = c.userUsecase.ChangeUserRole(ctx, appID, req.UserId, req.Role); err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.ChangeUserRoleResponse{
		Success: true,
	}, nil
}
