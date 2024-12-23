package grpc

import (
	"context"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/src/lib/e"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
)

func (c *controller) GetUser(ctx context.Context, req *ssov1.GetUserRequest) (*ssov1.GetUserResponse, error) {
	const method = "controller.gRPC.GetUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	user, err := c.userUsecase.GetUserByID(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserResponse(user), nil
}

// TODO: need to return a user data instead of empty struct
func (c *controller) UpdateUser(ctx context.Context, req *ssov1.UpdateUserRequest) (*ssov1.UpdateUserResponse, error) {
	const method = "controller.gRPC.UpdateUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateUpdateUserRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	userData := fromUpdateUserRequest(req)

	err = c.userUsecase.UpdateUser(ctx, appID, userData)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToUpdateUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.UpdateUserResponse{}, nil
}

func (c *controller) DeleteUser(ctx context.Context, req *ssov1.DeleteUserRequest) (*ssov1.DeleteUserResponse, error) {
	const method = "controller.gRPC.DeleteUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	err = c.userUsecase.DeleteUser(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToDeleteUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.DeleteUserResponse{}, nil
}
