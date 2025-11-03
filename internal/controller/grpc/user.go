package grpc

import (
	"context"

	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (c *gRPCController) GetUser(ctx context.Context, req *userv1.GetUserRequest) (*userv1.GetUserResponse, error) {
	const method = "controller.gRPC.GetUser"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
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

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateGetUserByIDRequest(r.(*userv1.GetUserByIDRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	user, err := c.userUsecase.GetUserByID(ctx, clientID, req.GetUserId())
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return toGetUserByIDResponse(user), nil
}

func (c *gRPCController) UpdateUser(ctx context.Context, req *userv1.UpdateUserRequest) (*userv1.UpdateUserResponse, error) {
	const method = "controller.gRPC.UpdateUser"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateUpdateUserRequest(r.(*userv1.UpdateUserRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
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
	const method = "controller.gRPC.DeleteUser"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
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

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateDeleteUserByIDRequest(r.(*userv1.DeleteUserByIDRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	err = c.userUsecase.DeleteUserByID(ctx, clientID, req.GetUserId())
	if err != nil {
		return nil, mapErrorToGRPCStatus(err)
	}

	return &userv1.DeleteUserByIDResponse{}, nil
}
