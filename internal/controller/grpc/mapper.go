package grpc

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/domain/entity"
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
