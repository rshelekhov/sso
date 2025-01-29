package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/sso/internal/controller"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/e"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (c *gRPCController) GetUser(ctx context.Context, req *ssov1.GetUserRequest) (*ssov1.GetUserResponse, error) {
	const method = "controller.gRPC.GetUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", controller.ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		// return nil, status.Errorf(codes.Internal, "%v: %v", controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	user, err := c.userUsecase.GetUserByID(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserResponse(user), nil
}

// TODO: need to return a user data instead of empty struct
func (c *gRPCController) UpdateUser(ctx context.Context, req *ssov1.UpdateUserRequest) (*ssov1.UpdateUserResponse, error) {
	const method = "сontroller.gRPC.UpdateUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateUpdateUserRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	userData := fromUpdateUserRequest(req)

	err = c.userUsecase.UpdateUser(ctx, appID, userData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToUpdateUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.UpdateUserResponse{}, nil
}

func (c *gRPCController) DeleteUser(ctx context.Context, req *ssov1.DeleteUserRequest) (*ssov1.DeleteUserResponse, error) {
	const method = "сontroller.gRPC.DeleteUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	err = c.userUsecase.DeleteUser(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToDeleteUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.DeleteUserResponse{}, nil
}
