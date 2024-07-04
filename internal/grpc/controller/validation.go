package controller

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TODO: refactor this methods for using general validator

// TODO: return all errors in one place

const emptyValue = ""

func validateLoginData(req *ssov1.LoginRequest, data *model.UserRequestData) error {
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

	data.Email = req.GetEmail()
	data.Password = req.GetPassword()
	data.AppID = req.GetAppId()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateRegisterData(req *ssov1.RegisterRequest, data *model.UserRequestData) error {
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

	data.Email = req.GetEmail()
	data.Password = req.GetPassword()
	data.AppID = req.GetAppId()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateLogout(req *ssov1.LogoutRequest, data *model.UserRequestData) error {
	// TODO: add validation with validator
	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	if req.UserDeviceData.GetUserAgent() == "" {
		return status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}

	if req.UserDeviceData.GetIp() == "" {
		return status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}

	data.AppID = req.GetAppId()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateRefresh(req *ssov1.RefreshRequest, data *model.RefreshRequestData) error {
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

	data.RefreshToken = req.GetRefreshToken()
	data.AppID = req.GetAppId()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateGetJWKS(req *ssov1.GetJWKSRequest, data *model.JWKSRequestData) error {
	// TODO: add validation with validator
	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	data.AppID = req.GetAppId()

	return nil
}

func validateGetUser(req *ssov1.GetUserRequest, data *model.UserRequestData) error {
	// TODO: add validation with validator
	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	data.AppID = req.GetAppId()

	return nil
}

func validateUpdateUser(req *ssov1.UpdateUserRequest, data *model.UserRequestData) error {
	// TODO: add validation with validator

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	data.Email = req.GetEmail()
	data.Password = req.GetCurrentPassword()
	data.UpdatedPassword = req.GetUpdatedPassword()
	data.AppID = req.GetAppId()

	// If UpdatedPassword is not empty, ensure Password is not empty
	if data.UpdatedPassword != "" && data.Password == "" {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}

	return nil
}

func validateDeleteUser(req *ssov1.DeleteUserRequest, data *model.UserRequestData) error {
	// TODO: add validation with validator
	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	if req.UserDeviceData.GetUserAgent() == "" {
		return status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}

	if req.UserDeviceData.GetIp() == "" {
		return status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}

	data.AppID = req.GetAppId()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}
