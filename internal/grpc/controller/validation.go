package controller

import (
	"strings"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const emptyValue = ""

func validateAppID(appID string) error {
	if appID == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}
	return nil
}

func validateUserCredentials(email, password string) error {
	if email == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrEmailIsRequired.Error())
	}
	if password == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}
	return nil
}

func validateUserDeviceData(userAgent, ip string) error {
	if userAgent == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}
	if ip == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}
	return nil
}

func validateRegisterAppData(req *ssov1.RegisterAppRequest) error {
	appName := req.GetAppName()

	if appName == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppNameIsRequired.Error())
	}
	if strings.Contains(appName, " ") {
		return status.Error(codes.InvalidArgument, le.ErrAppNameCannotContainSpaces.Error())
	}

	return nil
}

func validateVerifyEmailData(req *ssov1.VerifyEmailRequest, data *model.VerifyEmailRequestData) error {
	if req.GetVerificationToken() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrVerificationTokenIsRequired.Error())
	}

	data.VerificationToken = req.GetVerificationToken()
	return nil
}

func validateLoginData(req *ssov1.LoginRequest, data *model.UserRequestData) error {
	if err := validateUserCredentials(req.GetEmail(), req.GetPassword()); err != nil {
		return err
	}
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		return err
	}

	data.Email = req.GetEmail()
	data.Password = req.GetPassword()
	data.AppID = req.GetAppID()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateRegisterData(req *ssov1.RegisterUserRequest, data *model.UserRequestData) error {
	if err := validateUserCredentials(req.GetEmail(), req.GetPassword()); err != nil {
		return err
	}
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		return err
	}

	data.Email = req.GetEmail()
	data.Password = req.GetPassword()
	data.AppID = req.GetAppID()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateLogout(req *ssov1.LogoutRequest, data *model.UserRequestData) error {
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		return err
	}

	data.AppID = req.GetAppID()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateResetPasswordData(req *ssov1.ResetPasswordRequest, data *model.ResetPasswordRequestData) error {
	if req.GetEmail() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrEmailIsRequired.Error())
	}
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}

	data.Email = req.GetEmail()
	data.AppID = req.GetAppID()

	return nil
}

func validateChangePasswordData(req *ssov1.ChangePasswordRequest, data *model.ChangePasswordRequestData) error {
	if req.GetResetPasswordToken() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrResetPasswordTokenIsRequired.Error())
	}
	if req.GetUpdatedPassword() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}

	data.ResetPasswordToken = req.GetResetPasswordToken()
	data.UpdatedPassword = req.GetUpdatedPassword()
	data.AppID = req.GetAppID()

	return nil
}

func validateRefresh(req *ssov1.RefreshRequest, data *model.RefreshTokenRequestData) error {
	if req.GetRefreshToken() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrRefreshTokenIsRequired.Error())
	}
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		return err
	}

	data.RefreshToken = req.GetRefreshToken()
	data.AppID = req.GetAppID()
	data.UserDevice.UserAgent = req.UserDeviceData.GetUserAgent()
	data.UserDevice.IP = req.UserDeviceData.GetIp()

	return nil
}

func validateGetJWKS(req *ssov1.GetJWKSRequest, data *model.JWKSRequestData) error {
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}

	data.AppID = req.GetAppID()

	return nil
}

func validateGetUser(req *ssov1.GetUserRequest, data *model.UserRequestData) error {
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}

	data.AppID = req.GetAppID()

	return nil
}

func validateUpdateUser(req *ssov1.UpdateUserRequest, data *model.UserRequestData) error {
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}

	data.Email = req.GetEmail()
	data.Password = req.GetCurrentPassword()
	data.UpdatedPassword = req.GetUpdatedPassword()
	data.AppID = req.GetAppID()

	// If UpdatedPassword is not empty, ensure Password is not empty
	if data.UpdatedPassword != emptyValue && data.Password == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrCurrentPasswordIsRequired.Error())
	}

	return nil
}

func validateDeleteUser(req *ssov1.DeleteUserRequest, data *model.UserRequestData) error {
	if err := validateAppID(req.GetAppID()); err != nil {
		return err
	}

	data.AppID = req.GetAppID()

	return nil
}
