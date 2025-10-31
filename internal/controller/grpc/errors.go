package grpc

import (
	"errors"
	"fmt"

	commonv1 "github.com/rshelekhov/sso-protos/gen/go/api/common/v1"
	"github.com/rshelekhov/sso/internal/controller"
	"github.com/rshelekhov/sso/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorMapping defines the mapping between domain errors and gRPC error information
type errorMapping struct {
	grpcCode  codes.Code
	errorCode commonv1.ErrorCode
}

// domainErrorToProtoError maps domain errors to gRPC status codes and proto error codes.
// Only includes errors that clients need to handle differently.
// Other internal errors are logged via domain errors and return generic Internal status.
var domainErrorToProtoError = map[error]errorMapping{
	// Authentication errors
	domain.ErrInvalidCredentials: {
		codes.Unauthenticated,
		commonv1.ErrorCode_ERROR_CODE_INVALID_CREDENTIALS,
	},
	domain.ErrUserAlreadyExists: {
		codes.AlreadyExists,
		commonv1.ErrorCode_ERROR_CODE_USER_ALREADY_EXISTS,
	},
	domain.ErrUserNotFound: {
		codes.NotFound,
		commonv1.ErrorCode_ERROR_CODE_USER_NOT_FOUND,
	},
	domain.ErrSessionExpired: {
		codes.Unauthenticated,
		commonv1.ErrorCode_ERROR_CODE_SESSION_EXPIRED,
	},
	domain.ErrSessionNotFound: {
		codes.Unauthenticated,
		commonv1.ErrorCode_ERROR_CODE_SESSION_NOT_FOUND,
	},
	domain.ErrEmailAlreadyTaken: {
		codes.AlreadyExists,
		commonv1.ErrorCode_ERROR_CODE_EMAIL_ALREADY_TAKEN,
	},
	domain.ErrUserDeviceNotFound: {
		codes.NotFound,
		commonv1.ErrorCode_ERROR_CODE_USER_DEVICE_NOT_FOUND,
	},

	// Verification errors
	domain.ErrVerificationTokenNotFound: {
		codes.NotFound,
		commonv1.ErrorCode_ERROR_CODE_VERIFICATION_TOKEN_NOT_FOUND,
	},
	domain.ErrTokenExpiredWithEmailResent: {
		codes.FailedPrecondition,
		commonv1.ErrorCode_ERROR_CODE_TOKEN_EXPIRED_EMAIL_RESENT,
	},

	// Validation errors
	domain.ErrPasswordsDoNotMatch: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_PASSWORDS_DO_NOT_MATCH,
	},
	domain.ErrNoEmailChangesDetected: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_NO_EMAIL_CHANGES_DETECTED,
	},
	domain.ErrNoPasswordChangesDetected: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_NO_PASSWORD_CHANGES_DETECTED,
	},
	domain.ErrNoNameChangesDetected: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_NO_NAME_CHANGES_DETECTED,
	},
	domain.ErrClientIDIsNotAllowed: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_CLIENT_ID_NOT_ALLOWED,
	},
	domain.ErrCurrentPasswordRequired: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_CURRENT_PASSWORD_REQUIRED,
	},

	// Client management errors
	domain.ErrClientNotFound: {
		codes.NotFound,
		commonv1.ErrorCode_ERROR_CODE_CLIENT_NOT_FOUND,
	},
	domain.ErrClientAlreadyExists: {
		codes.AlreadyExists,
		commonv1.ErrorCode_ERROR_CODE_CLIENT_ALREADY_EXISTS,
	},
	domain.ErrClientNameIsEmpty: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_CLIENT_NAME_EMPTY,
	},

	// Internal service errors - only when clients need specific handling
	domain.ErrFailedToSendVerificationEmail: {
		codes.Internal,
		commonv1.ErrorCode_ERROR_CODE_FAILED_TO_SEND_VERIFICATION_EMAIL,
	},
	domain.ErrFailedToSendResetPasswordEmail: {
		codes.Internal,
		commonv1.ErrorCode_ERROR_CODE_FAILED_TO_SEND_RESET_PASSWORD_EMAIL,
	},

	// Controller errors - only validation and client lookup errors
	// Other controller errors (ErrFailedToGetRequestID, etc.) are internal/operational
	// and should return generic Internal status
	controller.ErrValidationError: {
		codes.InvalidArgument,
		commonv1.ErrorCode_ERROR_CODE_VALIDATION_ERROR,
	},
	controller.ErrClientNotFound: {
		codes.NotFound,
		commonv1.ErrorCode_ERROR_CODE_CLIENT_NOT_FOUND,
	},

	// Authentication context errors
	domain.ErrFailedToExtractUserIDFromContext: {
		codes.Unauthenticated,
		commonv1.ErrorCode_ERROR_CODE_SESSION_NOT_FOUND,
	},
}

// mapErrorToGRPCStatus converts domain errors to gRPC status errors with structured details.
// Errors not in the mapping are logged with their domain error (for debugging/metrics)
// and returned to clients as generic Internal errors.
func mapErrorToGRPCStatus(err error) error {
	if err == nil {
		return nil
	}

	// Check if this error needs specific client handling
	for domainErr, mapping := range domainErrorToProtoError {
		if errors.Is(err, domainErr) {
			return newGRPCStatusWithDetails(mapping.grpcCode, mapping.errorCode, err.Error(), nil)
		}
	}

	// Debug logging for unmapped errors
	fmt.Printf("DEBUG: No mapping found for error: %v, returning Internal\n", err)
	return status.Error(codes.Internal, "internal server error")
}

// newGRPCStatusWithDetails creates a gRPC status with error details attached
func newGRPCStatusWithDetails(
	code codes.Code,
	errorCode commonv1.ErrorCode,
	message string,
	metadata map[string]string,
) error {
	st := status.New(code, message)

	errDetail := &commonv1.ErrorDetail{
		Code:     errorCode,
		Message:  message,
		Metadata: metadata,
	}

	stWithDetails, err := st.WithDetails(errDetail)
	if err != nil {
		// If we can't attach details, return the status without details
		return st.Err()
	}

	return stWithDetails.Err()
}
