package grpc

import (
	"context"

	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/e"
)

func (c *gRPCController) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	const method = "controller.gRPC.Login"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateLoginRequest(r.(*authv1.LoginRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	userData := fromLoginRequest(req)

	userID, tokenData, err := c.authUsecase.Login(ctx, clientID, userData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToLoginUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toLoginResponse(userID, tokenData), nil
}

func (c *gRPCController) RegisterUser(ctx context.Context, req *authv1.RegisterUserRequest) (*authv1.RegisterUserResponse, error) {
	const method = "controller.gRPC.RegisterUser"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateRegisterUserRequest(r.(*authv1.RegisterUserRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	userData := fromRegisterUserRequest(req)
	endpoint := req.GetVerificationUrl()

	userID, tokenData, err := c.authUsecase.RegisterUser(ctx, clientID, userData, endpoint)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToRegisterUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toRegisterUserResponse(userID, tokenData), nil
}

func (c *gRPCController) VerifyEmail(ctx context.Context, req *authv1.VerifyEmailRequest) (*authv1.VerifyEmailResponse, error) {
	const method = "controller.gRPC.VerifyEmail"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateVerifyEmailRequest(r.(*authv1.VerifyEmailRequest))
	}); err != nil {
		return nil, err
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

	return &authv1.VerifyEmailResponse{}, nil
}

func (c *gRPCController) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {
	const method = "controller.gRPC.ResetPassword"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateResetPasswordRequest(r.(*authv1.ResetPasswordRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	reqData := fromResetPasswordRequest(req)
	endpoint := req.GetConfirmUrl()

	err = c.authUsecase.ResetPassword(ctx, clientID, reqData, endpoint)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToResetPassword, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &authv1.ResetPasswordResponse{}, nil
}

func (c *gRPCController) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	const method = "controller.gRPC.ChangePassword"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateChangePasswordRequest(r.(*authv1.ChangePasswordRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	reqData := fromChangePasswordRequest(req)

	res, err := c.authUsecase.ChangePassword(ctx, clientID, reqData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToChangePassword, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	if res.TokenExpired {
		return nil, mapErrorToGRPCStatus(domain.ErrTokenExpiredWithEmailResent)
	}

	return &authv1.ChangePasswordResponse{}, nil
}

func (c *gRPCController) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	const method = "controller.gRPC.Logout"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateLogoutRequest(r.(*authv1.LogoutRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	reqData := fromLogoutRequest(req)

	err = c.authUsecase.LogoutUser(ctx, clientID, reqData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToLogoutUser, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return &authv1.LogoutResponse{}, nil
}

func (c *gRPCController) RefreshTokens(ctx context.Context, req *authv1.RefreshTokensRequest) (*authv1.RefreshTokensResponse, error) {
	const method = "controller.gRPC.RefreshTokens"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	if err := c.validateRequest(ctx, log, req, func(r any) error {
		return validateRefreshRequest(r.(*authv1.RefreshTokensRequest))
	}); err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	reqData := fromRefreshRequest(req)

	tokenData, err := c.authUsecase.RefreshTokens(ctx, clientID, reqData)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToRefreshTokens, err)
		return nil, mapErrorToGRPCStatus(err)
	}
	return toRefreshTokensResponse(tokenData), nil
}

func (c *gRPCController) GetJWKS(ctx context.Context, req *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	const method = "controller.gRPC.GetJWKS"

	ctx, log, err := c.setupRequest(ctx, method)
	if err != nil {
		return nil, err
	}

	clientID, err := c.getAndValidateClientID(ctx, log)
	if err != nil {
		return nil, err
	}

	jwks, err := c.authUsecase.GetJWKS(ctx, clientID)
	if err != nil {
		e.LogError(ctx, log, controller.ErrFailedToGetJWKS, err)
		return nil, mapErrorToGRPCStatus(err)
	}

	return toJWKSResponse(jwks), nil
}
