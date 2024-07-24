package controller

import (
	"context"
	"errors"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *controller) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	userData := &model.UserRequestData{}
	if err := validateLoginData(req, userData); err != nil {
		return nil, err
	}

	tokenData, err := c.authUsecase.Login(ctx, userData)
	switch {
	case errors.Is(err, le.ErrUserNotFound):
		return nil, status.Error(codes.NotFound, le.ErrUserNotFound.Error())
	case errors.Is(err, le.ErrInvalidCredentials):
		return nil, status.Error(codes.Unauthenticated, le.ErrInvalidCredentials.Error())
	case errors.Is(err, le.ErrAppIDDoesNotExist):
		return nil, status.Error(codes.Unauthenticated, le.ErrAppIDDoesNotExist.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	tokenDataResponse := &ssov1.TokenData{
		AccessToken:      tokenData.AccessToken,
		RefreshToken:     tokenData.RefreshToken,
		Domain:           tokenData.Domain,
		Path:             tokenData.Path,
		ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
		HttpOnly:         tokenData.HTTPOnly,
		AdditionalFields: tokenData.AdditionalFields,
	}

	return &ssov1.LoginResponse{TokenData: tokenDataResponse}, nil
}

func (c *controller) RegisterUser(ctx context.Context, req *ssov1.RegisterUserRequest) (*ssov1.RegisterUserResponse, error) {
	userData := &model.UserRequestData{}
	if err := validateRegisterData(req, userData); err != nil {
		return nil, err
	}

	endpoint := req.GetVerifyEmailEndpoint()

	if endpoint == emptyValue {
		return nil, status.Error(codes.InvalidArgument, le.ErrEmailVerificationEndpointIsRequired.Error())
	}

	tokenData, err := c.authUsecase.RegisterUser(ctx, userData, endpoint)
	switch {
	case errors.Is(err, le.ErrUserAlreadyExists):
		return nil, status.Error(codes.AlreadyExists, le.ErrUserAlreadyExists.Error())
	case errors.Is(err, le.ErrAppIDDoesNotExist):
		return nil, status.Error(codes.Unauthenticated, le.ErrAppIDDoesNotExist.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	tokenDataResponse := &ssov1.TokenData{
		AccessToken:      tokenData.AccessToken,
		RefreshToken:     tokenData.RefreshToken,
		Domain:           tokenData.Domain,
		Path:             tokenData.Path,
		ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
		HttpOnly:         tokenData.HTTPOnly,
		AdditionalFields: tokenData.AdditionalFields,
	}

	return &ssov1.RegisterUserResponse{TokenData: tokenDataResponse}, nil
}

func (c *controller) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.Empty, error) {
	request := &model.UserRequestData{}
	if err := validateLogout(req, request); err != nil {
		return nil, err
	}

	err := c.authUsecase.LogoutUser(ctx, request.UserDevice, request.AppID)
	switch {
	case errors.Is(err, le.ErrFailedToGetUserIDFromToken):
		return nil, status.Error(codes.Internal, le.ErrFailedToGetUserIDFromToken.Error())
	case errors.Is(err, le.ErrUserDeviceNotFound):
		return nil, status.Error(codes.Internal, le.ErrUserDeviceNotFound.Error())
	case errors.Is(err, le.ErrFailedToDeleteSession):
		return nil, status.Error(codes.Internal, le.ErrFailedToDeleteSession.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	return &ssov1.Empty{}, nil
}

func (c *controller) Refresh(ctx context.Context, req *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	request := &model.RefreshRequestData{}
	if err := validateRefresh(req, request); err != nil {
		return nil, err
	}

	tokenData, err := c.authUsecase.RefreshTokens(ctx, request)
	switch {
	case errors.Is(err, le.ErrSessionNotFound):
		return nil, status.Error(codes.Unauthenticated, le.ErrSessionNotFound.Error())
	case errors.Is(err, le.ErrSessionExpired):
		return nil, status.Error(codes.Unauthenticated, le.ErrSessionExpired.Error())
	case errors.Is(err, le.ErrUserDeviceNotFound):
		return nil, status.Error(codes.Unauthenticated, le.ErrUserDeviceNotFound.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	tokenDataResponse := &ssov1.TokenData{
		AccessToken:      tokenData.AccessToken,
		RefreshToken:     tokenData.RefreshToken,
		Domain:           tokenData.Domain,
		Path:             tokenData.Path,
		ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
		HttpOnly:         tokenData.HTTPOnly,
		AdditionalFields: tokenData.AdditionalFields,
	}

	return &ssov1.RefreshResponse{TokenData: tokenDataResponse}, nil
}

func (c *controller) GetJWKS(ctx context.Context, req *ssov1.GetJWKSRequest) (*ssov1.GetJWKSResponse, error) {
	request := &model.JWKSRequestData{}
	if err := validateGetJWKS(req, request); err != nil {
		return nil, err
	}

	jwks, err := c.authUsecase.GetJWKS(ctx, request)
	if err != nil {
		if errors.Is(err, le.ErrFailedToGetJWKS) {
			return nil, status.Error(codes.Internal, le.ErrFailedToGetJWKS.Error())
		}
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	var jwksResponse []*ssov1.JWK

	for _, jwk := range jwks.Keys {
		jwkResponse := &ssov1.JWK{
			Kty: jwk.Kty,
			Kid: jwk.Kid,
			Use: jwk.Use,
			Alg: jwk.Alg,
			N:   jwk.N,
			E:   jwk.E,
		}
		jwksResponse = append(jwksResponse, jwkResponse)
	}

	return &ssov1.GetJWKSResponse{
		Jwks: jwksResponse,
		Ttl:  durationpb.New(jwks.TTL),
	}, nil
}

func (c *controller) GetUser(ctx context.Context, req *ssov1.GetUserRequest) (*ssov1.GetUserResponse, error) {
	request := &model.UserRequestData{}
	if err := validateGetUser(req, request); err != nil {
		return nil, err
	}

	user, err := c.authUsecase.GetUserByID(ctx, request)
	switch {
	case errors.Is(err, le.ErrFailedToGetUserIDFromToken):
		return nil, status.Error(codes.Internal, le.ErrFailedToGetUserIDFromToken.Error())
	case errors.Is(err, le.ErrUserNotFound):
		return nil, status.Error(codes.NotFound, le.ErrUserNotFound.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	return &ssov1.GetUserResponse{
		Email:     user.Email,
		UpdatedAt: timestamppb.New(user.UpdatedAt),
	}, nil
}

func (c *controller) UpdateUser(ctx context.Context, req *ssov1.UpdateUserRequest) (*ssov1.Empty, error) {
	request := &model.UserRequestData{}
	if err := validateUpdateUser(req, request); err != nil {
		return nil, err
	}

	err := c.authUsecase.UpdateUser(ctx, request)
	switch {
	case errors.Is(err, le.ErrFailedToGetUserIDFromToken):
		return nil, status.Error(codes.Internal, le.ErrFailedToGetUserIDFromToken.Error())
	case errors.Is(err, le.ErrUserNotFound):
		return nil, status.Error(codes.NotFound, le.ErrUserNotFound.Error())
	case errors.Is(err, le.ErrFailedToGetUserIDFromToken):
		return nil, status.Error(codes.Internal, le.ErrFailedToGetUserIDFromToken.Error())
	case errors.Is(err, le.ErrEmailAlreadyTaken):
		return nil, status.Error(codes.AlreadyExists, le.ErrEmailAlreadyTaken.Error())
	case errors.Is(err, le.ErrCurrentPasswordIsIncorrect):
		return nil, status.Error(codes.InvalidArgument, le.ErrCurrentPasswordIsIncorrect.Error())
	case errors.Is(err, le.ErrNoEmailChangesDetected):
		return nil, status.Error(codes.InvalidArgument, le.ErrNoEmailChangesDetected.Error())
	case errors.Is(err, le.ErrNoPasswordChangesDetected):
		return nil, status.Error(codes.InvalidArgument, le.ErrNoPasswordChangesDetected.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	return &ssov1.Empty{}, nil
}

func (c *controller) DeleteUser(ctx context.Context, req *ssov1.DeleteUserRequest) (*ssov1.Empty, error) {
	request := &model.UserRequestData{}
	if err := validateDeleteUser(req, request); err != nil {
		return nil, err
	}

	err := c.authUsecase.DeleteUser(ctx, request)
	switch {
	case errors.Is(err, le.ErrFailedToGetUserIDFromToken):
		return nil, status.Error(codes.Internal, le.ErrFailedToGetUserIDFromToken.Error())
	case errors.Is(err, le.ErrUserNotFound):
		return nil, status.Error(codes.NotFound, le.ErrUserNotFound.Error())
	case errors.Is(err, le.ErrUserDeviceNotFound):
		return nil, status.Error(codes.Internal, le.ErrUserDeviceNotFound.Error())
	case errors.Is(err, le.ErrFailedToDeleteSession):
		return nil, status.Error(codes.Internal, le.ErrFailedToDeleteSession.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	return &ssov1.Empty{}, nil
}
