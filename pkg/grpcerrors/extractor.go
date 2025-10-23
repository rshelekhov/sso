package grpcerrors

import (
	"errors"

	commonv1 "github.com/rshelekhov/sso-protos/gen/go/api/common/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrNotGRPCError is returned when the error is not a gRPC error
	ErrNotGRPCError = errors.New("not a gRPC error")

	// ErrNoErrorDetails is returned when the gRPC error has no details attached
	ErrNoErrorDetails = errors.New("no error details attached")
)

// ExtractedError contains all error information extracted from a gRPC error
type ExtractedError struct {
	// GRPCCode is the standard gRPC status code
	GRPCCode codes.Code

	// ErrorCode is the domain-specific error code from proto
	ErrorCode commonv1.ErrorCode

	// Message is the human-readable error message
	Message string

	// Metadata contains additional context about the error
	Metadata map[string]string

	// HasDetails indicates whether error details were found
	HasDetails bool
}

// ExtractError extracts all error information from a gRPC error
func ExtractError(err error) (*ExtractedError, error) {
	if err == nil {
		return nil, nil
	}

	// Convert to gRPC status
	st, ok := status.FromError(err)
	if !ok {
		return nil, ErrNotGRPCError
	}

	extracted := &ExtractedError{
		GRPCCode:   st.Code(),
		Message:    st.Message(),
		HasDetails: false,
	}

	// Try to extract error details
	for _, detail := range st.Details() {
		if errDetail, ok := detail.(*commonv1.ErrorDetail); ok {
			extracted.ErrorCode = errDetail.Code
			extracted.Metadata = errDetail.Metadata
			extracted.HasDetails = true
			break
		}
	}

	return extracted, nil
}

// GetErrorCode extracts only the error code from a gRPC error
func GetErrorCode(err error) (commonv1.ErrorCode, error) {
	extracted, err := ExtractError(err)
	if err != nil {
		return commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED, err
	}

	if !extracted.HasDetails {
		return commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED, ErrNoErrorDetails
	}

	return extracted.ErrorCode, nil
}

// IsErrorCode checks if the error matches a specific error code
func IsErrorCode(err error, code commonv1.ErrorCode) bool {
	extracted, extractErr := ExtractError(err)
	if extractErr != nil {
		return false
	}

	return extracted.HasDetails && extracted.ErrorCode == code
}

// IsGRPCCode checks if the error matches a specific gRPC code
func IsGRPCCode(err error, code codes.Code) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	return st.Code() == code
}
