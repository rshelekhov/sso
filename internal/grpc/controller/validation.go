package controller

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const emptyValue = 0

func validateLoginData(req *ssov1.LoginRequest, userInput *model.UserRequestData) error {
	// TODO: add validation with validator
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, le.ErrEmailIsRequired.Error())
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	if req.UserDeviceData.GetUserAgent() == "" {
		return status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}

	if req.UserDeviceData.GetIp() == "" {
		return status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}

	userInput = &model.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppID:    int(req.GetAppId()),
		UserDevice: model.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}

	return nil
}
func validateRegisterData(req *ssov1.RegisterRequest, userInput *model.UserRequestData) error {
	// TODO: add validation with validator
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, le.ErrEmailIsRequired.Error())
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	if req.UserDeviceData.GetUserAgent() == "" {
		return status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}

	if req.UserDeviceData.GetIp() == "" {
		return status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}

	userInput = &model.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppID:    int(req.GetAppId()),
		UserDevice: model.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}

	return nil
}

func validateRefresh(req *ssov1.RefreshRequest, request *model.RefreshRequestData) error {
	// TODO: add validation with validator
	if req.GetRefreshToken() == "" {
		return status.Error(codes.InvalidArgument, le.ErrRefreshTokenIsRequired.Error())
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	if req.UserDeviceData.GetUserAgent() == "" {
		return status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}

	if req.UserDeviceData.GetIp() == "" {
		return status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}

	request = &model.RefreshRequestData{
		RefreshToken: req.GetRefreshToken(),
		AppID:        int(req.GetAppId()),
		UserDevice: model.UserDeviceRequestData{
			UserAgent: req.UserDeviceData.GetUserAgent(),
			IP:        req.UserDeviceData.GetIp(),
		},
	}

	return nil
}
