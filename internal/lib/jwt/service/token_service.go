package service

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
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/segmentio/ksuid"
	"os"
	"time"
)

type ContextKey struct {
	name string
}

var TokenCtxKey = ContextKey{"Token"}

type TokenService struct {
	Issuer                   string
	SigningMethod            string
	KeysPath                 string
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	RefreshTokenCookieDomain string
	RefreshTokenCookiePath   string
	PasswordHashCost         int
	PasswordHashSalt         string
}

func NewJWTokenService(
	issuer string,
	signingMethod string,
	keysPath string,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
	refreshTokenCookieDomain string,
	refreshTokenCookiePath string,
	passwordHashCost int,
	passwordHashSalt string,
) *TokenService {
	return &TokenService{
		Issuer:                   issuer,
		SigningMethod:            signingMethod,
		KeysPath:                 keysPath,
		AccessTokenTTL:           accessTokenTTL,
		RefreshTokenTTL:          refreshTokenTTL,
		RefreshTokenCookieDomain: refreshTokenCookieDomain,
		RefreshTokenCookiePath:   refreshTokenCookiePath,
		PasswordHashCost:         passwordHashCost,
		PasswordHashSalt:         passwordHashSalt,
	}
}

func (ts *TokenService) Algorithm() jwt.SigningMethod {
	switch ts.SigningMethod {
	case "RS256":
		return jwt.SigningMethodRS256
	case "ES256":
		return jwt.SigningMethodES256
	default:
		return jwt.SigningMethodRS256
	}
}

func (ts *TokenService) NewAccessToken(appID int32, additionalClaims map[string]interface{}) (string, error) {
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

	return token.SignedString(privateKey)
}

func (ts *TokenService) GetKeyID(appID int32) (string, error) {
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

func (ts *TokenService) GetPublicKey(appID int32) (interface{}, error) {
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

func (ts *TokenService) getPublicKeyFromPEM(appID int32, keysPath string) (interface{}, error) {
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

func (ts *TokenService) NewRefreshToken() (string, error) {
	token := ksuid.New().String()
	return token, nil
}

func GetTokenFromContext(ctx context.Context) (*jwt.Token, error) {
	token, ok := ctx.Value(TokenCtxKey).(*jwt.Token)
	if !ok {
		return nil, le.ErrNoTokenFoundInCtx
	}

	return token, nil
}

func GetClaimsFromToken(ctx context.Context) (map[string]interface{}, error) {
	token, err := GetTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, le.ErrFailedToParseTokenClaims
	}

	return claims, nil
}

func GetUserID(ctx context.Context, key string) (string, error) {
	claims, err := GetClaimsFromToken(ctx)
	if err != nil {
		return "", err
	}

	userID, ok := claims[key]
	if !ok {
		return "", le.ErrUserIDNotFoundInCtx
	}

	return userID.(string), nil
}
