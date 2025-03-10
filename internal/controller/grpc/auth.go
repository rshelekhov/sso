package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/rshelekhov/sso/internal/controller"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (c *gRPCController) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	const method = "controller.gRPC.Login"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateLoginRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	userData := fromLoginRequest(req)

	tokenData, err := c.authUsecase.Login(ctx, appID, userData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToLoginUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toLoginResponse(tokenData), nil
}

func (c *gRPCController) RegisterUser(ctx context.Context, req *ssov1.RegisterUserRequest) (*ssov1.RegisterUserResponse, error) {
	const method = "controller.gRPC.RegisterUser"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateRegisterUserRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	userData := fromRegisterUserRequest(req)
	endpoint := req.GetVerificationUrl()

	tokenData, err := c.authUsecase.RegisterUser(ctx, appID, userData, endpoint)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToRegisterUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toRegisterUserResponse(tokenData), nil
}

func (c *gRPCController) VerifyEmail(ctx context.Context, req *ssov1.VerifyEmailRequest) (*ssov1.VerifyEmailResponse, error) {
	const method = "controller.gRPC.VerifyEmail"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateVerifyEmailRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	verificationToken := req.GetToken()

	res, err := c.authUsecase.VerifyEmail(ctx, verificationToken)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToVerifyEmail, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	if res.TokenExpired {
		return nil, mapErrorToGRPCStatus(domain.ErrTokenExpiredWithEmailResent)
	}

	return &ssov1.VerifyEmailResponse{}, nil
}

func (c *gRPCController) ResetPassword(ctx context.Context, req *ssov1.ResetPasswordRequest) (*ssov1.ResetPasswordResponse, error) {
	const method = "controller.gRPC.ResetPassword"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateResetPasswordRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	reqData := fromResetPasswordRequest(req)
	endpoint := req.GetConfirmUrl()

	err = c.authUsecase.ResetPassword(ctx, appID, reqData, endpoint)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToResetPassword, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.ResetPasswordResponse{}, nil
}

func (c *gRPCController) ChangePassword(ctx context.Context, req *ssov1.ChangePasswordRequest) (*ssov1.ChangePasswordResponse, error) {
	const method = "controller.gRPC.ChangePassword"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateChangePasswordRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	reqData := fromChangePasswordRequest(req)

	res, err := c.authUsecase.ChangePassword(ctx, appID, reqData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToChangePassword, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	if res.TokenExpired {
		return nil, mapErrorToGRPCStatus(domain.ErrTokenExpiredWithEmailResent)
	}

	return &ssov1.ChangePasswordResponse{}, nil
}

func (c *gRPCController) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	const method = "controller.gRPC.Logout"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateLogoutRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	reqData := fromLogoutRequest(req)

	err = c.authUsecase.LogoutUser(ctx, appID, reqData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToLogoutUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &ssov1.LogoutResponse{}, nil
}

func (c *gRPCController) Refresh(ctx context.Context, req *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	const method = "controller.gRPC.Refresh"

	log := c.log.With(slog.String("method", method))

	reqID, err := c.getRequestID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetRequestID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetRequestID, err))
	}

	log = log.With(slog.String("requestID", reqID))

	if err = validateRefreshRequest(req); err != nil {
		e.LogError(ctx, log, controller.ErrValidationError, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrValidationError, err))
	}

	appID, err := c.getAndValidateAppID(ctx)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetAndValidateAppID, err)
		return nil, mapErrorToGRPCStatus(fmt.Errorf("%w: %w", controller.ErrFailedToGetAndValidateAppID, err))
	}

	reqData := fromRefreshRequest(req)

	tokenData, err := c.authUsecase.RefreshTokens(ctx, appID, reqData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToRefreshTokens, err)
		return nil, mapErrorToGRPCStatus(err)
	}
	return toRefreshResponse(tokenData), nil
}

func (c *gRPCController) GetJWKS(ctx context.Context, req *ssov1.GetJWKSRequest) (*ssov1.GetJWKSResponse, error) {
	const method = "controller.gRPC.GetJWKS"

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

	jwks, err := c.authUsecase.GetJWKS(ctx, appID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetJWKS, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toJWKSResponse(jwks), nil
}
