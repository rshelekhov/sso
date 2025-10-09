package grpc

import (
	"errors"

	"github.com/rshelekhov/sso/internal/controller"

	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fromLoginRequest(req *authv1.LoginRequest) *entity.UserRequestData {
	return &entity.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}
}

func toLoginResponse(userID string, tokenData entity.SessionTokens) *authv1.LoginResponse {
	return &authv1.LoginResponse{
		UserId: userID,
		TokenData: &authv1.TokenData{
			AccessToken:      tokenData.AccessToken,
			RefreshToken:     tokenData.RefreshToken,
			Domain:           tokenData.Domain,
			Path:             tokenData.Path,
			ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
			HttpOnly:         tokenData.HTTPOnly,
			AdditionalFields: tokenData.AdditionalFields,
		},
	}
}

func fromRegisterUserRequest(req *authv1.RegisterUserRequest) *entity.UserRequestData {
	return &entity.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		Name:     req.GetName(),
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}
}

func toRegisterUserResponse(userID string, tokenData entity.SessionTokens) *authv1.RegisterUserResponse {
	return &authv1.RegisterUserResponse{
		UserId: userID,
		TokenData: &authv1.TokenData{
			AccessToken:      tokenData.AccessToken,
			RefreshToken:     tokenData.RefreshToken,
			Domain:           tokenData.Domain,
			Path:             tokenData.Path,
			ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
			HttpOnly:         tokenData.HTTPOnly,
			AdditionalFields: tokenData.AdditionalFields,
		},
	}
}

func fromResetPasswordRequest(req *authv1.ResetPasswordRequest) *entity.ResetPasswordRequestData {
	return &entity.ResetPasswordRequestData{
		Email: req.GetEmail(),
	}
}

func fromChangePasswordRequest(req *authv1.ChangePasswordRequest) *entity.ChangePasswordRequestData {
	return &entity.ChangePasswordRequestData{
		ResetPasswordToken: req.GetToken(),
		UpdatedPassword:    req.GetUpdatedPassword(),
	}
}

func fromLogoutRequest(req *authv1.LogoutRequest) *entity.UserDeviceRequestData {
	return &entity.UserDeviceRequestData{
		UserAgent: req.UserDeviceData.GetUserAgent(),
		IP:        req.UserDeviceData.GetIp(),
	}
}

func fromRefreshRequest(req *authv1.RefreshTokensRequest) *entity.RefreshTokenRequestData {
	return &entity.RefreshTokenRequestData{
		RefreshToken: req.GetRefreshToken(),
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}
}

func toRefreshTokensResponse(tokenData entity.SessionTokens) *authv1.RefreshTokensResponse {
	return &authv1.RefreshTokensResponse{
		TokenData: &authv1.TokenData{
			AccessToken:      tokenData.AccessToken,
			RefreshToken:     tokenData.RefreshToken,
			Domain:           tokenData.Domain,
			Path:             tokenData.Path,
			ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
			HttpOnly:         tokenData.HTTPOnly,
			AdditionalFields: tokenData.AdditionalFields,
		},
	}
}

func toJWKSResponse(jwks entity.JWKS) *authv1.GetJWKSResponse {
	var jwksResponse []*authv1.JWK

	for _, jwk := range jwks.Keys {
		jwkResponse := &authv1.JWK{
			Kty: jwk.Kty,
			Kid: jwk.Kid,
			Use: jwk.Use,
			Alg: jwk.Alg,
			N:   jwk.N,
			E:   jwk.E,
		}

		jwksResponse = append(jwksResponse, jwkResponse)
	}

	return &authv1.GetJWKSResponse{
		Jwks: jwksResponse,
	}
}

func toGetUserResponse(user entity.User) *userv1.GetUserResponse {
	return &userv1.GetUserResponse{
		User: &userv1.User{
			Id:        user.ID,
			Email:     user.Email,
			Verified:  user.Verified,
			UpdatedAt: timestamppb.New(user.UpdatedAt),
		},
	}
}

func fromUpdateUserRequest(req *userv1.UpdateUserRequest) entity.UserRequestData {
	return entity.UserRequestData{
		Email:           req.GetEmail(),
		Password:        req.GetCurrentPassword(),
		UpdatedPassword: req.GetUpdatedPassword(),
	}
}

func toUpdateUserResponse(user entity.User) *userv1.UpdateUserResponse {
	return &userv1.UpdateUserResponse{
		Email:     user.Email,
		UpdatedAt: timestamppb.New(user.UpdatedAt),
	}
}

func toGetUserByIDResponse(user entity.User) *userv1.GetUserByIDResponse {
	return &userv1.GetUserByIDResponse{
		User: &userv1.User{
			Id:        user.ID,
			Email:     user.Email,
			Verified:  user.Verified,
			UpdatedAt: timestamppb.New(user.UpdatedAt),
		},
	}
}

var errorToStatus = map[error]codes.Code{
	domain.ErrUserNotFound:                codes.NotFound,
	domain.ErrInvalidCredentials:          codes.Unauthenticated,
	domain.ErrUserAlreadyExists:           codes.AlreadyExists,
	domain.ErrVerificationTokenNotFound:   codes.NotFound,
	domain.ErrUserDeviceNotFound:          codes.NotFound,
	domain.ErrSessionNotFound:             codes.Unauthenticated,
	domain.ErrSessionExpired:              codes.Unauthenticated,
	domain.ErrUserDeviceNotFound:          codes.Unauthenticated,
	domain.ErrEmailAlreadyTaken:           codes.AlreadyExists,
	domain.ErrPasswordsDoNotMatch:         codes.InvalidArgument,
	domain.ErrNoEmailChangesDetected:      codes.InvalidArgument,
	domain.ErrNoPasswordChangesDetected:   codes.InvalidArgument,
	domain.ErrTokenExpiredWithEmailResent: codes.FailedPrecondition,
	domain.ErrClientIDIsNotAllowed:        codes.InvalidArgument,
}

func mapErrorToGRPCStatus(err error) error {
	if errors.Is(err, controller.ErrValidationError) {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	for domainErr, statusCode := range errorToStatus {
		if errors.Is(err, domainErr) {
			return status.Error(statusCode, domainErr.Error())
		}
	}

	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	return nil
}
