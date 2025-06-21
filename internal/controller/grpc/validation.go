package grpc

import (
	"errors"
	"fmt"
	"strings"

	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const emptyValue = ""

var (
	ErrEmailIsRequired                             = errors.New("email is required")
	ErrPasswordIsRequired                          = errors.New("password is required")
	ErrUserAgentIsRequired                         = errors.New("user agent is required")
	ErrIPIsRequired                                = errors.New("ip is required")
	ErrUserIDIsRequired                            = errors.New("user_id is required")
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

func validateRegisterClientRequest(req *clientv1.RegisterClientRequest) error {
	appName := req.GetClientName()

	if appName == emptyValue {
		return status.Error(codes.InvalidArgument, ErrAppNameIsRequired.Error())
	}
	if strings.Contains(appName, " ") {
		return status.Error(codes.InvalidArgument, ErrAppNameCannotContainSpaces.Error())
	}

	return nil
}

func validateVerifyEmailRequest(req *authv1.VerifyEmailRequest) error {
	if req.GetToken() == emptyValue {
		return ErrVerificationTokenIsRequired
	}

	return nil
}

func validateLoginRequest(req *authv1.LoginRequest) error {
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

func validateRegisterUserRequest(req *authv1.RegisterUserRequest) error {
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

func validateLogoutRequest(req *authv1.LogoutRequest) error {
	if err := validateUserDeviceData(req.UserDeviceData.GetUserAgent(), req.UserDeviceData.GetIp()); err != nil {
		return err
	}

	return nil
}

func validateResetPasswordRequest(req *authv1.ResetPasswordRequest) error {
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

func validateChangePasswordRequest(req *authv1.ChangePasswordRequest) error {
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

func validateRefreshRequest(req *authv1.RefreshTokensRequest) error {
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

func validateGetUserByIDRequest(req *userv1.GetUserByIDRequest) error {
	if req.GetUserId() == "" {
		return status.Error(codes.InvalidArgument, ErrUserIDIsRequired.Error())
	}
	return nil
}

func validateUpdateUserRequest(req *userv1.UpdateUserRequest) error {
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

func validateDeleteUserByIDRequest(req *userv1.DeleteUserByIDRequest) error {
	if req.GetUserId() == "" {
		return status.Error(codes.InvalidArgument, ErrUserIDIsRequired.Error())
	}
	return nil
}
