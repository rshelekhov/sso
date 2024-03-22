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

	ErrUserAlreadyExists            LocalError = "user already exists"
	ErrFailedToCheckIfPasswordMatch LocalError = "failed to check if password match"
	ErrPasswordsDontMatch           LocalError = "invalid credentials: passwords don't match"
	ErrInvalidCredentials           LocalError = "invalid credentials"
	ErrFailedToCreateUser           LocalError = "failed to create user"
	ErrFailedToGeneratePasswordHash LocalError = "failed to generate password hash"
	ErrFailedToGetUserByEmail       LocalError = "failed to get user by email"
	ErrFailedToGetDeviceID          LocalError = "failed to get device id"

	ErrFailedToCreateAccessToken   LocalError = "failed to create access token"
	ErrFailedToCreateRefreshToken  LocalError = "failed to create refresh token"
	ErrUserDeviceNotFound          LocalError = "user device not found"
	ErrFailedToUpdateLastVisitedAt LocalError = "failed to update last visited at"
	ErrFailedToCreateUserSession   LocalError = "failed to create user session"
)
