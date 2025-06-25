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
	// Client storage errors
	// ===========================================================================

	ErrClientIDDoesNotExist = errors.New("client ID does not exist")
	ErrClientAlreadyExists  = errors.New("client already exists")
	ErrClientNotFound       = errors.New("client not found")

	// ===========================================================================
	// User storage errors
	// ===========================================================================

	ErrUserNotFound = errors.New("user not found")

	// ===========================================================================
	// Verification storage errors
	// ===========================================================================

	ErrVerificationTokenNotFound = errors.New("verification token not found")
)
