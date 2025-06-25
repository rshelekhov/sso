package grpc

import (
	"context"
	"fmt"
	"log/slog"

	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (c *gRPCController) GetUser(ctx context.Context, req *userv1.GetUserRequest) (*userv1.GetUserResponse, error) {
	const method = "controller.gRPC.GetUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	clientID, err := c.getAndValidateClientID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateClientID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateClientID, err))
	}

	user, err := c.userUsecase.GetUser(ctx, clientID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserResponse(user), nil
}

func (c *gRPCController) GetUserByID(ctx context.Context, req *userv1.GetUserByIDRequest) (*userv1.GetUserByIDResponse, error) {
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

	clientID, err := c.getAndValidateClientID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateClientID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateClientID, err))
	}

	user, err := c.userUsecase.GetUserByID(ctx, clientID, req.GetUserId())
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserByIDResponse(user), nil
}

func (c *gRPCController) UpdateUser(ctx context.Context, req *userv1.UpdateUserRequest) (*userv1.UpdateUserResponse, error) {
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

	clientID, err := c.getAndValidateClientID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateClientID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateClientID, err))
	}

	userData := fromUpdateUserRequest(req)

	updatedUser, err := c.userUsecase.UpdateUser(ctx, clientID, userData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToUpdateUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toUpdateUserResponse(updatedUser), nil
}

func (c *gRPCController) DeleteUser(ctx context.Context, req *userv1.DeleteUserRequest) (*userv1.DeleteUserResponse, error) {
	const method = "сontroller.gRPC.DeleteUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	clientID, err := c.getAndValidateClientID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateClientID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateClientID, err))
	}

	err = c.userUsecase.DeleteUser(ctx, clientID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToDeleteUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &userv1.DeleteUserResponse{}, nil
}

func (c *gRPCController) DeleteUserByID(ctx context.Context, req *userv1.DeleteUserByIDRequest) (*userv1.DeleteUserByIDResponse, error) {
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

	clientID, err := c.getAndValidateClientID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateClientID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateClientID, err))
	}

	err = c.userUsecase.DeleteUserByID(ctx, clientID, req.GetUserId())
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &userv1.DeleteUserByIDResponse{}, nil
}
