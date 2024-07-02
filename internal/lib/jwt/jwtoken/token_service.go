package jwtoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/segmentio/ksuid"
	"google.golang.org/grpc/metadata"
	"os"
	"strings"
	"time"
)

type ContextKey struct {
	name string
}

const (
	AccessTokenKey = "access_token"
	Kid            = "kid"
)

func (c ContextKey) String() string {
	return c.name
}

type Service struct {
	Issuer                   string
	SigningMethod            string
	KeysPath                 string
	JWKSetTTL                time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	RefreshTokenCookieDomain string
	RefreshTokenCookiePath   string
	PasswordHashCost         int
	PasswordHashSalt         string
}

func NewService(
	issuer string,
	signingMethod string,
	keysPath string,
	JWKSetTTL time.Duration,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshTokenCookieDomain string,
	refreshTokenCookiePath string,
	passwordHashCost int,
	passwordHashSalt string,
) *Service {
	return &Service{
		Issuer:                   issuer,
		SigningMethod:            signingMethod,
		KeysPath:                 keysPath,
		JWKSetTTL:                JWKSetTTL,
		AccessTokenTTL:           accessTokenTTL,
		RefreshTokenTTL:          refreshTokenTTL,
		RefreshTokenCookieDomain: refreshTokenCookieDomain,
		RefreshTokenCookiePath:   refreshTokenCookiePath,
		PasswordHashCost:         passwordHashCost,
		PasswordHashSalt:         passwordHashSalt,
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

func (ts *Service) NewAccessToken(appID int32, kid string, additionalClaims map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{}

	if additionalClaims != nil { // nolint:gosimple
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	filePath := fmt.Sprintf("%s/app_%d_private.pem", ts.KeysPath, appID)

	// TODO: add logic for creating keys
	// check if private key exists
	// if not, create them and save to file
	// also generate public key and save to file

	privateKeyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse rsa private key from pem: %w", err)
	}

	token := jwt.NewWithClaims(ts.Algorithm(), claims)

	token.Header[Kid] = kid

	return token.SignedString(privateKey)
}

func (ts *Service) GetKeyID(appID int32) (string, error) {
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

func (ts *Service) GetPublicKey(appID int32) (interface{}, error) {
	pub, err := ts.getPublicKeyFromPEM(appID, ts.KeysPath)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	case *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, le.ErrUnknownTypeOfPublicKey
	}
}

func (ts *Service) getPublicKeyFromPEM(appID int32, keysPath string) (interface{}, error) {
	// Construct the complete file path based on the AppID and provided keysPath
	filePath := fmt.Sprintf("%s/app_%d_public.pem", keysPath, appID)

	// Read the public key from the PEM file
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Decode the PEM data to get the public key
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, le.ErrFailedToDecodePEM
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, le.ErrFailedToParsePKIXPublicKey
	}

	return pub, nil
}

func (ts *Service) NewRefreshToken() (string, error) {
	token := ksuid.New().String()
	return token, nil
}

func (ts *Service) GetUserID(ctx context.Context, appID int32, key string) (string, error) {
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

func (ts *Service) GetClaimsFromToken(ctx context.Context, appID int32) (map[string]interface{}, error) {
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

func (ts *Service) GetTokenFromContext(ctx context.Context, appID int32) (*jwt.Token, error) {
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

func (ts *Service) ParseToken(s string, appID int32) (*jwt.Token, error) {
	tokenString := strings.TrimSpace(s)
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ts.GetPublicKey(appID)
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
