package grpc

import (
	"context"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/src/lib/e"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
)

func (c *controller) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	const method = "controller.gRPC.Login"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateLoginRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	userData := fromLoginRequest(req)

	tokenData, err := c.authUsecase.Login(ctx, appID, userData)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToLoginUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toLoginResponse(tokenData), nil
}

func (c *controller) RegisterUser(ctx context.Context, req *ssov1.RegisterUserRequest) (*ssov1.RegisterUserResponse, error) {
	const method = "controller.gRPC.RegisterUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateRegisterUserRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	userData := fromRegisterUserRequest(req)
	endpoint := req.GetVerificationUrl()

	tokenData, err := c.authUsecase.RegisterUser(ctx, appID, userData, endpoint)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToRegisterUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toRegisterUserResponse(tokenData), nil
}

func (c *controller) VerifyEmail(ctx context.Context, req *ssov1.VerifyEmailRequest) (*ssov1.VerifyEmailResponse, error) {
	const method = "controller.gRPC.VerifyEmail"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateVerifyEmailRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	verificationToken := req.GetToken()

	err = c.authUsecase.VerifyEmail(ctx, verificationToken)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToVerifyEmail, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.VerifyEmailResponse{}, nil
}

func (c *controller) ResetPassword(ctx context.Context, req *ssov1.ResetPasswordRequest) (*ssov1.ResetPasswordResponse, error) {
	const method = "controller.gRPC.ResetPassword"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateResetPasswordRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	reqData := fromResetPasswordRequest(req)
	endpoint := req.GetConfirmUrl()

	err = c.authUsecase.ResetPassword(ctx, appID, reqData, endpoint)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToResetPassword, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.ResetPasswordResponse{}, nil
}

func (c *controller) ChangePassword(ctx context.Context, req *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	const method = "controller.gRPC.ChangePassword"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateChangePasswordRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	reqData := fromChangePasswordRequest(req)

	err = c.authUsecase.ChangePassword(ctx, appID, reqData)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToChangePassword, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.ChangePasswordResponse{}, nil
}

func (c *controller) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	const method = "controller.gRPC.Logout"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateLogoutRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	reqData := fromLogoutRequest(req)

	err = c.authUsecase.LogoutUser(ctx, appID, reqData)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToLogoutUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.LogoutResponse{}, nil
}

func (c *controller) Refresh(ctx context.Context, req *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	const method = "controller.gRPC.Refresh"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetRequestID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetRequestID, err)
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateRefreshRequest(req); err != nil {
		e.HandleError(ctx, log, ErrValidationError, err)
		return nil, status.Errorf(codes.InvalidArgument, "%v: %v", ErrValidationError, err)
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetAndValidateAppID, err)
		return nil, status.Errorf(codes.Internal, "%v: %v", ErrFailedToGetAndValidateAppID, err)
	}

	reqData := fromRefreshRequest(req)

	tokenData, err := c.authUsecase.RefreshTokens(ctx, appID, reqData)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToRefreshTokens, err)
		return nil, mapErrorToGRPCStatus(err)
	}
	return toRefreshResponse(tokenData), nil
}

func (c *controller) GetJWKS(ctx context.Context, req *ssov1.GetJWKSRequest) (*ssov1.GetJWKSResponse, error) {
	const method = "controller.gRPC.GetJWKS"

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

	jwks, err := c.authUsecase.GetJWKS(ctx, appID)
	if err != nil {
		e.HandleError(ctx, log, ErrFailedToGetJWKS, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toJWKSResponse(jwks), nil
}
