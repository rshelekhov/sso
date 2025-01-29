package grpc

import (
	"errors"
	"fmt"
	"strings"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const emptyValue = ""

var (
	ErrEmailIsRequired                             = errors.New("email is required")
	ErrPasswordIsRequired                          = errors.New("password is required")
	ErrUserAgentIsRequired                         = errors.New("user agent is required")
	ErrIPIsRequired                                = errors.New("ip is required")
	ErrEmailVerificationEndpointIsRequired         = errors.New("email verification endpoint is required")
	ErrVerificationTokenIsRequired                 = errors.New("verification token is required")
	ErrResetPasswordConfirmationEndpointIsRequired = errors.New("reset password confirmation endpoint is required")
	ErrResetPasswordTokenIsRequired                = errors.New("reset password token is required")
	ErrRefreshTokenIsRequired                      = errors.New("refresh token is required")
	ErrCurrentPasswordIsRequired                   = errors.New("current password is required")
	ErrAppNameIsRequired                           = errors.New("app name is required")
	ErrAppNameCannotContainSpaces                  = errors.New("app name cannot contain spaces")
)

func validateUserCredentials(email, password string) error {
	var errMessages []string

	if email == emptyValue {
		errMessages = append(errMessages, ErrEmailIsRequired.Error())
	}

	if password == emptyValue {
		errMessages = append(errMessages, ErrPasswordIsRequired.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateUserDeviceData(userAgent, ip string) error {
	var errMessages []string

	if userAgent == emptyValue {
		errMessages = append(errMessages, ErrUserAgentIsRequired.Error())
	}

	if ip == emptyValue {
		errMessages = append(errMessages, ErrIPIsRequired.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateRegisterAppRequest(req *ssov1.RegisterAppRequest) error {
	appName := req.GetAppName()

	if appName == emptyValue {
		return status.Error(codes.InvalidArgument, ErrAppNameIsRequired.Error())
	}
	if strings.Contains(appName, " ") {
		return status.Error(codes.InvalidArgument, ErrAppNameCannotContainSpaces.Error())
	}

	return nil
}

func validateVerifyEmailRequest(req *ssov1.VerifyEmailRequest) error {
	if req.GetToken() == emptyValue {
		return ErrVerificationTokenIsRequired
	}

	return nil
}

func validateLoginRequest(req *ssov1.LoginRequest) error {
	var errMessages []string

	if err := validateUserCredentials(req.GetEmail(), req.GetPassword()); err != nil {
		errMessages = append(errMessages, err.Error())
	}
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		errMessages = append(errMessages, err.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateRegisterUserRequest(req *ssov1.RegisterUserRequest) error {
	var errMessages []string

	if err := validateUserCredentials(req.GetEmail(), req.GetPassword()); err != nil {
		errMessages = append(errMessages, err.Error())
	}
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		errMessages = append(errMessages, err.Error())
	}

	if req.GetVerificationUrl() == emptyValue {
		errMessages = append(errMessages, ErrEmailVerificationEndpointIsRequired.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateLogoutRequest(req *ssov1.LogoutRequest) error {
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		return err
	}

	return nil
}

func validateResetPasswordRequest(req *ssov1.ResetPasswordRequest) error {
	var errMessages []string

	if req.GetEmail() == emptyValue {
		errMessages = append(errMessages, ErrEmailIsRequired.Error())
	}

	if req.GetConfirmUrl() == emptyValue {
		errMessages = append(errMessages, ErrResetPasswordConfirmationEndpointIsRequired.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateChangePasswordRequest(req *ssov1.ChangePasswordRequest) error {
	var errMessages []string

	if req.GetToken() == emptyValue {
		errMessages = append(errMessages, ErrResetPasswordTokenIsRequired.Error())
	}

	if req.GetUpdatedPassword() == emptyValue {
		errMessages = append(errMessages, ErrPasswordIsRequired.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateRefreshRequest(req *ssov1.RefreshRequest) error {
	var errMessages []string

	if req.GetRefreshToken() == emptyValue {
		errMessages = append(errMessages, ErrRefreshTokenIsRequired.Error())
	}

	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		errMessages = append(errMessages, err.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}

func validateUpdateUserRequest(req *ssov1.UpdateUserRequest) error {
	var errMessages []string

	password := req.GetCurrentPassword()
	updatedPassword := req.GetUpdatedPassword()

	// If UpdatedPassword is not empty, ensure Password is not empty
	if updatedPassword != emptyValue && password == emptyValue {
		errMessages = append(errMessages, ErrCurrentPasswordIsRequired.Error())
	}

	if len(errMessages) > 0 {
		return fmt.Errorf("%s", strings.Join(errMessages, "; "))
	}

	return nil
}
