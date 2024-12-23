package storage

import "errors"

var (
	// ===========================================================================
	// Session storage errors
	// ===========================================================================

	ErrUserDeviceNotFound = errors.New("user device not found")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionsNotFound   = errors.New("sessions not found")

	// ===========================================================================
	// App storage errors
	// ===========================================================================

	ErrAppIDDoesNotExist = errors.New("app ID does not exist")
	ErrAppAlreadyExists  = errors.New("app already exists")
	ErrAppNotFound       = errors.New("app not found")

	// ===========================================================================
	// User storage errors
	// ===========================================================================

	ErrUserNotFound = errors.New("user not found")

	// ===========================================================================
	// Verification storage errors
	// ===========================================================================

	ErrVerificationTokenNotFound = errors.New("verification token not found")
)
