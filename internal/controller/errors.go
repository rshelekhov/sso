package controller

import "errors"

var (
	ErrValidationError             = errors.New("validation error")
	ErrRequestIDNotFoundInContext  = errors.New("request ID not found in context")
	ErrAppIDNotFoundInContext      = errors.New("app ID not found in context")
	ErrFailedToGetRequestID        = errors.New("failed to get requestID")
	ErrFailedToGetAppID            = errors.New("failed to get appID")
	ErrFailedToValidateAppID       = errors.New("failed to validate appID")
	ErrFailedToGetAndValidateAppID = errors.New("failed to get and validate appID")
	ErrAppNotFound                 = errors.New("app not found")

	ErrFailedToLoginUser      = errors.New("failed to login user")
	ErrFailedToRegisterUser   = errors.New("failed to register user")
	ErrFailedToVerifyEmail    = errors.New("failed to verify email")
	ErrFailedToResetPassword  = errors.New("failed to reset password")
	ErrFailedToChangePassword = errors.New("failed to change password")
	ErrFailedToLogoutUser     = errors.New("failed to logout user")
	ErrFailedToRefreshTokens  = errors.New("failed to refresh tokens")
	ErrFailedToGetJWKS        = errors.New("failed to get JWKS")

	ErrFailedToGetUser    = errors.New("failed to get user")
	ErrFailedToUpdateUser = errors.New("failed to update user")
	ErrFailedToDeleteUser = errors.New("failed to delete user")
)
