package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/pkg/jwtauth/cache"
	"google.golang.org/grpc/metadata"
)

type manager struct {
	// JWKS provider for fetching JWKS
	jwksProvider JWKSProvider

	// Cache to store JWKS
	jwksCache *cache.Cache

	// Mutex for thread-safe cache operations
	mu sync.RWMutex

	// App ID for verification tokens
	// This is optional field is using in a services, authenticated by SSO
	clientID string

	// Recorder for token validation metrics
	metrics MetricsRecorder
}

func NewManager(jwksProvider JWKSProvider, opts ...Option) Manager {
	m := &manager{
		jwksProvider: jwksProvider,
		jwksCache:    cache.New(),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

type Option func(m *manager)

func WithClientID(clientID string) Option {
	return func(m *manager) {
		m.clientID = clientID
	}
}

func WithMetricsRecorder(metrics MetricsRecorder) Option {
	return func(m *manager) {
		m.metrics = metrics
	}
}

const (
	AuthorizationHeader = "authorization"
	ClientIDHeader      = "x-client-id"  // Lowercase to match grpc-gateway forwarding

	AccessTokenKey  = "access_token"
	RefreshTokenKey = "refresh_token"
	UserIDKey       = "user_id"

	TokenCtxKey = "token"

	KidTokenHeader = "kid"
	AlgTokenHeader = "alg"
)

// ExtractTokenFromGRPC retrieves the JWT token from gRPC metadata.
// It accepts the token in two formats for flexibility:
// 1. "Bearer <token>" (HTTP-style, forwarded by grpc-gateway)
// 2. "<token>" (native gRPC style)
func (m *manager) ExtractTokenFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoGRPCMetadata
	}

	values := md.Get(AuthorizationHeader)
	if len(values) == 0 {
		return "", ErrAuthorizationHeaderNotFoundInGRPCMetadata
	}

	token := values[0]
	// Strip "Bearer " prefix if present (for HTTP requests via grpc-gateway)
	if len(token) > 7 && strings.ToUpper(token[0:6]) == "BEARER" {
		return token[7:], nil
	}
	// Otherwise return token as-is (for native gRPC clients)
	return token, nil
}

// ExtractTokenFromHTTP retrieves the JWT token from the "Authorization" HTTP header.
// It expects the token to be in the format "Bearer <token>".
func (m *manager) ExtractTokenFromHTTP(r *http.Request) (string, error) {
	token := r.Header.Get(AuthorizationHeader)
	if token == "" {
		return "", ErrAuthorizationHeaderNotFoundInHTTPRequest
	}
	if len(token) > 7 && strings.ToUpper(token[0:6]) == "BEARER" {
		return token[7:], nil
	}
	return "", ErrBearerTokenNotFound
}

// ExtractTokenFromCookies retrieves the JWT token from a cookie named "access_token".
func (m *manager) ExtractTokenFromCookies(r *http.Request) (string, error) {
	cookie, err := r.Cookie(AccessTokenKey)
	if err != nil {
		return "", fmt.Errorf("failed to get cookie: %w", err)
	}

	return cookie.Value, nil
}

// ExtractRefreshTokenFromCookies retrieves the refresh token from a cookie named "refresh_token".
func (m *manager) ExtractRefreshTokenFromCookies(r *http.Request) (string, error) {
	cookie, err := r.Cookie(RefreshTokenKey)
	if err != nil {
		return "", fmt.Errorf("failed to get cookie: %w", err)
	}

	return cookie.Value, nil
}

// FromContext returns token from context
func (m *manager) FromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(TokenCtxKey).(string)
	return token, ok
}

// ToContext adds the given token to the context.
func (m *manager) ToContext(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, TokenCtxKey, value)
}

// TokenFromContext retrieves the token string from context.
// This is useful when you need to forward the token to other services
// or perform token-specific operations (e.g., revocation checks).
// Returns empty string if token is not found.
func TokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(TokenCtxKey).(string)
	return token
}

// ParseToken parses the given access token string and validates
// it using the public keys (JWKS). It checks the "kid" (key ID)
// in the token header to select the appropriate public key.
func (m *manager) ParseToken(clientID, token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (any, error) {
		kidRaw, ok := token.Header[KidTokenHeader]
		if !ok {
			return nil, ErrKidNotFoundInTokenHeader
		}

		kid, ok := kidRaw.(string)
		if !ok {
			return nil, ErrKidIsNotAString
		}

		jwk, err := m.getJWK(context.Background(), clientID, kid)
		if err != nil {
			return nil, err
		}

		// Decode the base64 URL-encoded components of the RSA public key
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, err
		}

		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, err
		}

		// Construct the RSA public key from the decoded components
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}

		// Verify that the token uses RSA signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header[AlgTokenHeader])
		}

		return pubKey, nil
	})
}

// ExtractUserID retrieves the user ID from the token claims.
func (m *manager) ExtractUserID(ctx context.Context, clientID string) (string, error) {
	claims, err := m.getClaimsFromToken(ctx, clientID)
	if err != nil {
		return "", err
	}

	userID, ok := claims[UserIDKey].(string)
	if !ok {
		return "", ErrUserIDNotFoundInToken
	}

	return userID, nil
}

// getClaimsFromToken returns the claims of the provided access token.
func (m *manager) getClaimsFromToken(ctx context.Context, clientID string) (map[string]any, error) {
	tokenString, ok := m.FromContext(ctx)
	if !ok {
		return nil, ErrTokenNotFoundInContext
	}

	token, err := m.ParseToken(clientID, tokenString)
	if err != nil {
		return nil, Errors(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrFailedToParseTokenClaims
	}

	return claims, nil
}

func (m *manager) recordTokenSuccess(ctx context.Context, clientID string) {
	if m.metrics != nil {
		m.metrics.RecordTokenValidationSuccess(ctx, clientID)
	}
}

func (m *manager) recordTokenExpired(ctx context.Context, clientID string) {
	if m.metrics != nil {
		m.metrics.RecordTokenValidationExpired(ctx, clientID)
	}
}

func (m *manager) recordTokenInvalid(ctx context.Context, clientID string) {
	if m.metrics != nil {
		m.metrics.RecordTokenValidationInvalid(ctx, clientID)
	}
}

func (m *manager) recordTokenMalformed(ctx context.Context, clientID string) {
	if m.metrics != nil {
		m.metrics.RecordTokenValidationMalformed(ctx, clientID)
	}
}

func (m *manager) recordTokenValidationDuration(ctx context.Context, clientID string, duration float64) {
	if m.metrics != nil {
		m.metrics.RecordTokenValidationDuration(ctx, clientID, duration)
	}
}

func Errors(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return jwt.ErrTokenExpired
	case errors.Is(err, jwt.ErrSignatureInvalid):
		return jwt.ErrSignatureInvalid
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return jwt.ErrTokenNotValidYet
	default:
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
}
