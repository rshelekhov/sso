package jwtoken

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/config/settings"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/port"
	"github.com/segmentio/ksuid"
	"google.golang.org/grpc/metadata"
)

type ContextKey struct {
	name string
}

const (
	AccessTokenKey = "access_token"
	Kid            = "kid"
	emptyValue     = ""
)

func (c ContextKey) String() string {
	return c.name
}

type TokenService interface {
	Algorithm() jwt.SigningMethod
	NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error)
	GeneratePrivateKey(appID string) error
	GetKeyID(appID string) (string, error)
	GetPublicKey(appID string) (interface{}, error)
	NewRefreshToken() (string, error)
	GetUserID(ctx context.Context, appID, key string) (string, error)
	GetClaimsFromToken(ctx context.Context, appID string) (map[string]interface{}, error)
	GetTokenFromContext(ctx context.Context, appID string) (*jwt.Token, error)
	ParseToken(tokenString, appID string) (*jwt.Token, error)
}

type Service struct {
	Issuer                   string
	SigningMethod            string
	KeyStorage               port.KeyStorage
	PasswordHashParams       settings.PasswordHashParams
	JWKSetTTL                time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	RefreshTokenCookieDomain string
	RefreshTokenCookiePath   string
}

func NewService(
	issuer string,
	signingMethod string,
	keyStorage port.KeyStorage,
	passwordHashParams settings.PasswordHashParams,
	jwksTTL time.Duration,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshTokenCookieDomain string,
	refreshTokenCookiePath string,
) *Service {
	return &Service{
		Issuer:                   issuer,
		SigningMethod:            signingMethod,
		KeyStorage:               keyStorage,
		PasswordHashParams:       passwordHashParams,
		JWKSetTTL:                jwksTTL,
		AccessTokenTTL:           accessTokenTTL,
		RefreshTokenTTL:          refreshTokenTTL,
		RefreshTokenCookieDomain: refreshTokenCookieDomain,
		RefreshTokenCookiePath:   refreshTokenCookiePath,
	}
}

func (ts *Service) Algorithm() jwt.SigningMethod {
	switch ts.SigningMethod {
	case "RS256":
		return jwt.SigningMethodRS256
	case "ES256":
		return jwt.SigningMethodES256
	default:
		return jwt.SigningMethodRS256
	}
}

func (ts *Service) NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error) {
	if kid == emptyValue {
		return "", le.ErrEmptyKidIsNotAllowed
	}

	claims := jwt.MapClaims{}

	if additionalClaims != nil { // nolint:gosimple
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	privateKeyPEM, err := ts.KeyStorage.GetPrivateKey(appID)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse rsa private key from pem: %w", err)
	}

	token := jwt.NewWithClaims(ts.Algorithm(), claims)

	token.Header[Kid] = kid

	return token.SignedString(privateKey)
}

func (ts *Service) GetKeyID(appID string) (string, error) {
	if appID == emptyValue {
		return "", le.ErrEmptyAppIDIsNotAllowed
	}

	// Get public key
	pub, err := ts.GetPublicKey(appID)
	if err != nil {
		return "", err
	}

	// Create key ID
	var keyID string
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		s := sha1.Sum(der)
		keyID = base64.URLEncoding.EncodeToString(s[:])
	}

	return keyID, err
}

func (ts *Service) NewRefreshToken() (string, error) {
	token := ksuid.New().String()
	return token, nil
}

func (ts *Service) GetUserID(ctx context.Context, appID, key string) (string, error) {
	claims, err := ts.GetClaimsFromToken(ctx, appID)
	if err != nil {
		return "", err
	}

	userID, ok := claims[key]
	if !ok {
		return "", le.ErrUserIDNotFoundInCtx
	}

	return userID.(string), nil
}

func (ts *Service) GetClaimsFromToken(ctx context.Context, appID string) (map[string]interface{}, error) {
	token, err := ts.GetTokenFromContext(ctx, appID)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, le.ErrFailedToParseTokenClaims
	}

	return claims, nil
}

func (ts *Service) GetTokenFromContext(ctx context.Context, appID string) (*jwt.Token, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, le.ErrNoMetaDataFoundInCtx
	}

	tokenString := md.Get(AccessTokenKey)

	if len(tokenString) == 0 {
		return nil, le.ErrNoTokenFoundInMetadata
	}

	token, err := ts.ParseToken(tokenString[0], appID)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (ts *Service) ParseToken(s, appID string) (*jwt.Token, error) {
	tokenString := strings.TrimSpace(s)

	//nolint:revive
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ts.GetPublicKey(appID)
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
