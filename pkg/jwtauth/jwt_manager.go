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
	"github.com/rshelekhov/jwtauth/cache"
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

const (
	AuthorizationHeader = "authorization"
	ClientIDHeader      = "X-Client-ID"

	AccessTokenKey  = "access_token"
	RefreshTokenKey = "refresh_token"
	UserIDKey       = "user_id"

	TokenCtxKey = "Token"

	KidTokenHeader = "kid"
	AlgTokenHeader = "alg"
)

// ExtractTokenFromGRPC retrieves the JWT token from gRPC metadata.
// It expects the token to be in the "X-Access-Token" header.
func (m *manager) ExtractTokenFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoGRPCMetadata
	}

	values := md.Get(AuthorizationHeader)
	if len(values) == 0 {
		return "", ErrAuthorizationHeaderNotFoundInGRPCMetadata
	}

	return values[0], nil
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

// ParseToken parses the given access token string and validates it using the public keys (JWKS).
// It checks the "kid" (key ID) in the token header to select the appropriate public key.
func (m *manager) ParseToken(clientID, token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
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
func (m *manager) getClaimsFromToken(ctx context.Context, clientID string) (map[string]interface{}, error) {
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

// verifyToken checks the validity of the provided access token.
// It parses the token, verifies the signature, and ensures it is not expired.
func (m *manager) verifyToken(clientID, token string) error {
	parsedToken, err := m.ParseToken(clientID, token)
	if err != nil {
		return Errors(err)
	}

	if !parsedToken.Valid {
		return ErrInvalidToken
	}

	return nil
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
