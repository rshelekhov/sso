package jwtauth

import "errors"

var (
	ErrInvalidToken  = errors.New("invalid token")
	ErrTokenNotFound = errors.New("token not found")
	ErrUnauthorized  = errors.New("unauthorized")

	ErrNoGRPCMetadata                            = errors.New("no gRPC metadata")
	ErrAuthorizationHeaderNotFoundInGRPCMetadata = errors.New("authorization header not found in gRPC metadata")
	ErrAuthorizationHeaderNotFoundInHTTPRequest  = errors.New("authorization header not found in HTTP request")
	ErrBearerTokenNotFound                       = errors.New("bearer token not found")
	ErrAppIDHeaderNotFoundInGRPCMetadata         = errors.New("app ID header not found in gRPC metadata")
	ErrAppIDHeaderNotFoundInHTTPRequest          = errors.New("app ID header not found in HTTP request")

	ErrKidNotFoundInTokenHeader = errors.New("kid not found in token header")
	ErrKidIsNotAString          = errors.New("kid is not a string")
	ErrUnexpectedSigningMethod  = errors.New("unexpected signing method")

	ErrUserIDNotFoundInToken    = errors.New("user ID not found in token")
	ErrTokenNotFoundInContext   = errors.New("token not found in context")
	ErrFailedToParseTokenClaims = errors.New("failed to parse token claims")
)
