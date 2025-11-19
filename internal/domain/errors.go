package domain

import "errors"

var (
	ErrFailedToCommitTransaction = errors.New("failed to commit transaction")

	// ===========================================================================
	// Client validator service errors
	// ===========================================================================

	ErrClientNotFound = errors.New("client not found")

	// ===========================================================================
	// Session service errors
	// ===========================================================================

	ErrFailedToGetDeviceID              = errors.New("failed to get device ID")
	ErrFailedToGetKeyID                 = errors.New("failed to get key ID")
	ErrFailedToGetSessionByRefreshToken = errors.New("failed to check session and device")
	ErrFailedToCreateAccessToken        = errors.New("failed to create access token")
	ErrFailedToCreateUserSession        = errors.New("failed to create user session")
	ErrFailedToUpdateLastVisitedAt      = errors.New("failed to update last visited at")
	ErrSessionExpired                   = errors.New("session expired")
	ErrSessionNotFound                  = errors.New("session not found")
	ErrUserDeviceNotFound               = errors.New("user device not found")
	ErrFailedToDeleteRefreshToken       = errors.New("failed to delete refresh token")
	ErrFailedToDeleteSession            = errors.New("failed to delete session")
	ErrFailedToValidateClientID         = errors.New("failed to validate client ID")
	ErrFailedToRegisterDevice           = errors.New("failed to register device")

	// ===========================================================================
	// User service errors
	// ===========================================================================

	ErrUserNotFound        = errors.New("user not found")
	ErrFailedToGetUserByID = errors.New("failed to get user by ID")

	// ===========================================================================
	// Token service errors
	// ===========================================================================

	ErrClientIDIsNotAllowed             = errors.New("clientID is not allowed")
	ErrEmptyKidIsNotAllowed             = errors.New("kid is not allowed")
	ErrFailedToGetPrivateKey            = errors.New("failed to get private key")
	ErrFailedToParsePrivateKey          = errors.New("failed to parse private key")
	ErrFailedToSignToken                = errors.New("failed to sign token")
	ErrPasswordIsNotAllowed             = errors.New("password is not allowed")
	ErrHashIsNotAllowed                 = errors.New("hash is not allowed")
	ErrFailedToGenerateSalt             = errors.New("failed to generate salt")
	ErrUnsupportedPasswordHashType      = errors.New("unsupported password hash type")
	ErrFailedToHashPassword             = errors.New("failed to hash password")
	ErrInvalidArgonHashString           = errors.New("invalid argon hash string")
	ErrUnSupportedArgon2Version         = errors.New("unsupported Argon2 version")
	ErrUserIDNotFoundInContext          = errors.New("user id not found in context")
	ErrFailedToParseTokenClaims         = errors.New("failed to parse token claims")
	ErrNoTokenFoundInContext            = errors.New("token not found in context")
	ErrFailedToParseTokenWithClaims     = errors.New("failed to parse token with claims")
	ErrUnknownTypeOfPublicKey           = errors.New("unknown type of public key")
	ErrFailedToExtractUserIDFromContext = errors.New("failed to extract user ID from context")

	// ===========================================================================
	// Verification service errors
	// ===========================================================================

	ErrFailedToCreateVerificationToken     = errors.New("failed to create verification token")
	ErrFailedToSaveVerificationToken       = errors.New("failed to save verification token")
	ErrFailedToGenerateVerificationToken   = errors.New("failed to generate verification token")
	ErrFailedToProcessToken                = errors.New("failed to process token")
	ErrVerificationTokenNotFound           = errors.New("token not found")
	ErrFailedToGetVerificationTokenData    = errors.New("failed to get verification token data")
	ErrFailedToDeleteVerificationToken     = errors.New("failed to delete verification token")
	ErrFailedToDeleteAllVerificationTokens = errors.New("failed to delete all verification tokens")

	// ===========================================================================
	// Client usecase errors
	// ===========================================================================

	ErrClientNameIsEmpty                 = errors.New("client name is empty")
	ErrClientAlreadyExists               = errors.New("client already exists")
	ErrFailedToGenerateSecretHash        = errors.New("failed to generate secret hash")
	ErrFailedToRegisterClient            = errors.New("failed to register client")
	ErrFailedToGenerateAndSavePrivateKey = errors.New("failed to generate and save private key")
	ErrFailedToDeleteClient              = errors.New("failed to delete client")

	// ===========================================================================
	// Auth usecase errors
	// ===========================================================================

	ErrUserAlreadyExists                  = errors.New("user already exists")
	ErrFailedToReplaceSoftDeletedUser     = errors.New("failed to replace soft deleted user")
	ErrFailedToRegisterUser               = errors.New("failed to register user")
	ErrFailedToGetUserByEmail             = errors.New("failed to get user by email")
	ErrInvalidCredentials                 = errors.New("invalid credentials")
	ErrFailedToCheckPasswordHashAndUpdate = errors.New("failed to check password hash and update")
	ErrFailedToVerifyPassword             = errors.New("failed to verify password")
	ErrFailedToSendEmail                  = errors.New("failed to send email")
	ErrFailedToSendVerificationEmail      = errors.New("failed to send verification email")
	ErrFailedToSendResetPasswordEmail     = errors.New("failed to send reset password email")
	ErrFailedToMarkEmailVerified          = errors.New("failed to mark email as verified")
	ErrTokenExpiredWithEmailResent        = errors.New("token expired, a new email with a new token has been sent to the user")
	ErrFailedToGetPublicKey               = errors.New("failed to get public key")
	ErrFailedToGetJWKS                    = errors.New("failed to get jwks")
	ErrInvalidVerificationURL             = errors.New("invalid verification URL")
	ErrFailedToBuildVerificationURL       = errors.New("failed to build verification URL")

	// ===========================================================================
	// User usecase errors
	// ===========================================================================

	ErrFailedToGetUser                = errors.New("failed to get user")
	ErrFailedToGetUserData            = errors.New("failed to get user data")
	ErrFailedToUpdateUser             = errors.New("failed to update user")
	ErrPasswordsDoNotMatch            = errors.New("passwords do not match")
	ErrNoPasswordChangesDetected      = errors.New("no password changes detected")
	ErrCurrentPasswordRequired        = errors.New("current password is required")
	ErrFailedToCheckPasswordHashMatch = errors.New("failed to check password hash match")
	ErrFailedToGeneratePasswordHash   = errors.New("failed to generate password hash")
	ErrFailedToGetUserStatusByEmail   = errors.New("failed to get user status by email")
	ErrNoEmailChangesDetected         = errors.New("no email changes detected")
	ErrNoNameChangesDetected          = errors.New("no name changes detected")
	ErrEmailAlreadyTaken              = errors.New("email already taken")
	ErrFailedToGetUserStatusByID      = errors.New("failed to get user status by ID")
	ErrUnknownUserStatus              = errors.New("unknown user status")
	ErrFailedToCleanupUserData        = errors.New("failed to cleanup user data")
	ErrFailedToDeleteUser             = errors.New("failed to delete user")
	ErrFailedToDeleteAllUserSessions  = errors.New("failed to delete all user sessions")
	ErrFailedToDeleteUserDevices = errors.New("failed to delete user devices")
	ErrFailedToDeleteUserTokens  = errors.New("failed to delete tokens")
	ErrFailedToSearchUsers       = errors.New("failed to search users")
	ErrFailedToCountSearchUsers  = errors.New("failed to count search users")
)
