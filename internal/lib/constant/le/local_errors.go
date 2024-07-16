package le

type LocalError string

func (l LocalError) Error() string {
	return string(l)
}

const (
	ErrInternalServerError LocalError = "internal server error"

	// ===========================================================================
	//	storage errors
	// ===========================================================================

	ErrLocalKeyStorageSettingsEmpty LocalError = "local key storage settings is empty"
	ErrS3KeyStorageSettingsEmpty    LocalError = "s3 key storage settings is empty"
	ErrFailedToCommitTransaction    LocalError = "failed to commit transaction"

	// ===========================================================================
	//	app errors
	// ===========================================================================

	ErrAppIDIsRequired            LocalError = "appID is required"
	ErrAppIDDoesNotExist          LocalError = "appID does not exist"
	ErrAppNameIsRequired          LocalError = "appName is required"
	ErrAppNameCannotContainSpaces LocalError = "appName cannot contain spaces"
	ErrFailedToGenerateSecretHash LocalError = "failed to generate secret hash"

	ErrAppAlreadyExists LocalError = "app already exists"
	ErrAppNotFound      LocalError = "app not found"

	// ===========================================================================
	//	auth errors
	// ===========================================================================

	ErrUserAgentIsRequired    LocalError = "user-agent is required"
	ErrIPIsRequired           LocalError = "ip is required"
	ErrEmailIsRequired        LocalError = "email is required"
	ErrPasswordIsRequired     LocalError = "password is required"
	ErrRefreshTokenIsRequired LocalError = "refresh_token is required"

	ErrUserAlreadyExists            LocalError = "user already exists"
	ErrPasswordsDoNotMatch          LocalError = "invalid credentials: passwords don't match"
	ErrCurrentPasswordIsIncorrect   LocalError = "invalid credentials: current password is incorrect"
	ErrInvalidCredentials           LocalError = "invalid credentials"
	ErrEmailAlreadyTaken            LocalError = "email already taken"
	ErrFailedToCreateUser           LocalError = "failed to create user"
	ErrFailedToGeneratePasswordHash LocalError = "failed to generate password hash"
	ErrFailedToGetUserByEmail       LocalError = "failed to get user by email"
	ErrFailedToGetUser              LocalError = "failed to get user"
	ErrFailedToCheckIfPasswordMatch LocalError = "failed to check if password match"
	ErrUserNotFound                 LocalError = "user not found"
	ErrNoEmailChangesDetected       LocalError = "no changes detected"
	ErrNoPasswordChangesDetected    LocalError = "no password changes detected"
	ErrFailedToCheckEmailUniqueness LocalError = "failed to check email uniqueness"
	ErrFailedToDeleteUser           LocalError = "failed to delete user"

	// ===========================================================================
	//	JWT service errors
	// ===========================================================================

	ErrFailedToGetAppSignKey         LocalError = "failed to get app sign key"
	ErrFailedToCreateAccessToken     LocalError = "failed to create access jwtoken"
	ErrFailedToCreateRefreshToken    LocalError = "failed to create refresh jwtoken"
	ErrUserDeviceNotFound            LocalError = "user device not found"
	ErrFailedToUpdateLastVisitedAt   LocalError = "failed to update last visited at"
	ErrFailedToCreateUserSession     LocalError = "failed to create user session"
	ErrSessionNotFound               LocalError = "session not found"
	ErrSessionExpired                LocalError = "session expired"
	ErrFailedToCheckSessionAndDevice LocalError = "failed to check session and device"
	ErrFailedToDeleteRefreshToken    LocalError = "failed to delete refresh jwtoken"
	ErrFailedToGetUserIDFromToken    LocalError = "failed to get user id from jwtoken"
	ErrFailedToGetDeviceID           LocalError = "failed to get device id"
	ErrFailedToDeleteSession         LocalError = "failed to delete session"
	ErrUnknownTypeOfPublicKey        LocalError = "unknown type of public key"
	ErrFailedToGetJWKS               LocalError = "failed to get jwks"
	ErrFailedToGetKeyID              LocalError = "failed to get key id"

	ErrNoMetaDataFoundInCtx        LocalError = "no metadata found in ctx"
	ErrNoTokenFoundInMetadata      LocalError = "no token found in metadata"
	ErrFailedToParseTokenClaims    LocalError = "failed to parse jwtoken claims"
	ErrUserIDNotFoundInCtx         LocalError = "user id not found in ctx"
	ErrFailedToGetRequestIDFromCtx LocalError = "failed to get request id from ctx"
	ErrRequestIDNotFoundInCtx      LocalError = "request id not found in ctx"
)
