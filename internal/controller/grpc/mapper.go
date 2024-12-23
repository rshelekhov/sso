package grpc

import (
	"errors"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/src/domain"
	"github.com/rshelekhov/sso/src/domain/entity"
	"github.com/rshelekhov/sso/src/lib/constant/le"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func fromLoginRequest(req *ssov1.LoginRequest) *entity.UserRequestData {
	return &entity.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}
}

func toLoginResponse(tokenData entity.SessionTokens) *ssov1.LoginResponse {
	return &ssov1.LoginResponse{
		TokenData: &ssov1.TokenData{
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

func fromRegisterUserRequest(req *ssov1.RegisterUserRequest) *entity.UserRequestData {
	return &entity.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}
}

func toRegisterUserResponse(tokenData entity.SessionTokens) *ssov1.RegisterUserResponse {
	return &ssov1.RegisterUserResponse{
		TokenData: &ssov1.TokenData{
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

func fromResetPasswordRequest(req *ssov1.ResetPasswordRequest) *entity.ResetPasswordRequestData {
	return &entity.ResetPasswordRequestData{
		Email: req.GetEmail(),
	}
}

func fromChangePasswordRequest(req *ssov1.ChangePasswordRequest) *entity.ChangePasswordRequestData {
	return &entity.ChangePasswordRequestData{
		ResetPasswordToken: req.GetToken(),
		UpdatedPassword:    req.GetUpdatedPassword(),
	}
}

func fromLogoutRequest(req *ssov1.LogoutRequest) *entity.UserDeviceRequestData {
	return &entity.UserDeviceRequestData{
		UserAgent: req.UserDeviceData.GetUserAgent(),
		IP:        req.UserDeviceData.GetIp(),
	}
}

func fromRefreshRequest(req *ssov1.RefreshRequest) *entity.RefreshTokenRequestData {
	return &entity.RefreshTokenRequestData{
		RefreshToken: req.GetRefreshToken(),
		UserDevice: entity.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}
}

func toRefreshResponse(tokenData entity.SessionTokens) *ssov1.RefreshResponse {
	return &ssov1.RefreshResponse{
		TokenData: &ssov1.TokenData{
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

func toJWKSResponse(jwks entity.JWKS) *ssov1.GetJWKSResponse {
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
	}
}

func toGetUserResponse(user entity.User) *ssov1.GetUserResponse {
	return &ssov1.GetUserResponse{
		Email:     user.Email,
		Verified:  user.Verified,
		UpdatedAt: timestamppb.New(user.UpdatedAt),
	}
}

func fromUpdateUserRequest(req *ssov1.UpdateUserRequest) *entity.UserRequestData {
	return &entity.UserRequestData{
		Email:           req.GetEmail(),
		Password:        req.GetCurrentPassword(),
		UpdatedPassword: req.GetUpdatedPassword(),
	}
}

// TODO: replace errors with a domain errors instead of this
var errorToStatus = map[error]codes.Code{
	domain.ErrUserNotFound:              codes.NotFound,
	le.ErrInvalidCredentials:            codes.Unauthenticated,
	le.ErrUserAlreadyExists:             codes.AlreadyExists,
	le.ErrTokenExpiredWithEmailResent:   codes.FailedPrecondition,
	le.ErrTokenNotFound:                 codes.NotFound,
	domain.ErrUserDeviceNotFound:        codes.NotFound,
	domain.ErrSessionNotFound:           codes.Unauthenticated,
	domain.ErrSessionExpired:            codes.Unauthenticated,
	domain.ErrUserDeviceNotFound:        codes.Unauthenticated,
	domain.ErrEmailAlreadyTaken:         codes.AlreadyExists,
	domain.ErrPasswordsDoNotMatch:       codes.InvalidArgument,
	domain.ErrNoEmailChangesDetected:    codes.InvalidArgument,
	domain.ErrNoPasswordChangesDetected: codes.InvalidArgument,
}

func mapErrorToGRPCStatus(err error) error {
	for domainErr, statusCode := range errorToStatus {
		if errors.Is(err, domainErr) {
			return status.Error(statusCode, domainErr.Error())
		}
	}

	if err != nil {
		return status.Error(codes.Internal, "internal server error")
	}

	return nil
}
