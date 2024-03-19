package le

type LocalError string

func (l LocalError) Error() string {
	return string(l)
}

const (
	// ===========================================================================
	//	auth errors
	// ===========================================================================

	ErrFailedToExtractMetaData LocalError = "failed to extract metadata from context"
	ErrRequestIDIsRequired     LocalError = "request-id is required"
	ErrUserAgentIsRequired     LocalError = "user-agent is required"
	ErrIPIsRequired            LocalError = "ip is required"
	ErrEmailIsRequired         LocalError = "email is required"
	ErrPasswordIsRequired      LocalError = "password is required"
	ErrAppIDIsRequired         LocalError = "app_id is required"
)
