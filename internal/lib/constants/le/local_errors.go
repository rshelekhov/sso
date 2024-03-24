package le

type LocalError string

func (l LocalError) Error() string {
	return string(l)
}

const (
	ErrInternalServerError LocalError = "internal server error"

	// ===========================================================================
	//	auth errors
	// ===========================================================================

	ErrFailedToExtractMetaData LocalError = "failed to extract metadata from context"
	ErrValidationFailed        LocalError = "validation failed"
	ErrRequestIDIsRequired     LocalError = "request-id is required"
	ErrUserAgentIsRequired     LocalError = "user-agent is required"
	ErrIPIsRequired            LocalError = "ip is required"
	ErrEmailIsRequired         LocalError = "email is required"
	ErrPasswordIsRequired      LocalError = "password is required"
	ErrAppIDIsRequired         LocalError = "app_id is required"
	ErrRefreshTokenIsRequired  LocalError = "refresh_token is required"

	ErrUserAlreadyExists            LocalError = "user already exists"
	ErrPasswordsDontMatch           LocalError = "invalid credentials: passwords don't match"
	ErrInvalidCredentials           LocalError = "invalid credentials"
	ErrEmailAlreadyTaken            LocalError = "email already taken"
	ErrFailedToCreateUser           LocalError = "failed to create user"
	ErrFailedToGeneratePasswordHash LocalError = "failed to generate password hash"
	ErrFailedToGetUserByEmail       LocalError = "failed to get user by email"
	ErrFailedToGetUser              LocalError = "failed to get user"
	ErrFailedToCheckIfPasswordMatch LocalError = "failed to check if password match"
	ErrUserNotFound                 LocalError = "user not found"
	ErrNoChangesDetected            LocalError = "no changes detected"
	ErrNoPasswordChangesDetected    LocalError = "no password changes detected"

	ErrFailedToCreateAccessToken     LocalError = "failed to create access token"
	ErrFailedToCreateRefreshToken    LocalError = "failed to create refresh token"
	ErrUserDeviceNotFound            LocalError = "user device not found"
	ErrFailedToUpdateLastVisitedAt   LocalError = "failed to update last visited at"
	ErrFailedToCreateUserSession     LocalError = "failed to create user session"
	ErrSessionNotFound               LocalError = "session not found"
	ErrSessionExpired                LocalError = "session expired"
	ErrFailedToCheckSessionAndDevice LocalError = "failed to check session and device"
	ErrFailedToDeleteRefreshToken    LocalError = "failed to delete refresh token"
	ErrFailedToGetUserIDFromToken    LocalError = "failed to get user id from token"
	ErrFailedToGetDeviceID           LocalError = "failed to get device id"
)
