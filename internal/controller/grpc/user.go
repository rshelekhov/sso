package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/sso/internal/controller"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (c *gRPCController) GetUser(ctx context.Context, req *ssov1.GetUserRequest) (*ssov1.GetUserResponse, error) {
	const method = "controller.gRPC.GetUser"

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

	user, err := c.userUsecase.GetUser(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserResponse(user), nil
}

func (c *gRPCController) GetUserByID(ctx context.Context, req *ssov1.GetUserByIDRequest) (*ssov1.GetUserByIDResponse, error) {
	const method = "controller.gRPC.GetUserByID"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateGetUserByIDRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	user, err := c.userUsecase.GetUserByID(ctx, appID, req.GetUserId())
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserByIDResponse(user), nil
}

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

	updatedUser, err := c.userUsecase.UpdateUser(ctx, appID, userData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToUpdateUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toUpdateUserResponse(updatedUser), nil
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

func (c *gRPCController) DeleteUserByID(ctx context.Context, req *ssov1.DeleteUserByIDRequest) (*ssov1.DeleteUserByIDResponse, error) {
	const method = "controller.gRPC.DeleteUserByID"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateDeleteUserByIDRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	err = c.userUsecase.DeleteUserByID(ctx, appID, req.GetUserId())
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.DeleteUserByIDResponse{}, nil
}
