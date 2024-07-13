package jwtoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
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

const (
	privateKeyFilePathFormat = "%s/app_%s_private.pem"
	publicKeyFilePathFormat  = "%s/app_%s_public.pem"
)

func (ts *Service) NewAccessToken(appID, kid string, additionalClaims map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{}

	if additionalClaims != nil { // nolint:gosimple
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	filePath := fmt.Sprintf(privateKeyFilePathFormat, ts.KeysPath, appID)

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

func (ts *Service) GeneratePEMKeyPair(appID string) error {
	privateKeyFilePath := fmt.Sprintf(privateKeyFilePathFormat, ts.KeysPath, appID)
	publicKeyFilePath := fmt.Sprintf(publicKeyFilePathFormat, ts.KeysPath, appID)

	// Ensure the keysPath directory exists
	if err := os.MkdirAll(ts.KeysPath, os.ModePerm); err != nil {
		return err
	}

	// Check if the private key exists
	if _, err := os.Stat(privateKeyFilePath); os.IsNotExist(err) {
		// Private key does not exist, create it
		privateKey, err := generateAndSavePrivateKey(privateKeyFilePath)
		if err != nil {
			return err
		}

		// Generate public key
		if err = generateAndSavePublicKey(privateKey, publicKeyFilePath); err != nil {
			return err
		}
	}

	return nil
}

func generateAndSavePrivateKey(filePath string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Save private key to file
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create a PEM block with the DER encoded private key
	b64 := []byte(base64.StdEncoding.EncodeToString(privateKeyBytes))
	privatePEM := fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s-----END PRIVATE KEY-----\n", make64ColsString(b64))

	if err := os.WriteFile(filePath, []byte(privatePEM), 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key to file: %w", err)
	}

	return privateKey, nil
}

func generateAndSavePublicKey(privateKey *rsa.PrivateKey, filePath string) error {
	publicKey := &privateKey.PublicKey

	// Marshal public key to PKIX, ASN.1 DER form
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create a PEM block with the DER encoded public key
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Encode the PEM block to bytes
	publicPEM := pem.EncodeToMemory(pemBlock)

	// Write the PEM file
	if err := os.WriteFile(filePath, []byte(publicPEM), 0644); err != nil {
		return fmt.Errorf("failed to save public key to file: %w", err)
	}

	return nil
}

func make64ColsString(slice []byte) string {
	chunks := chunkSlice(slice, 64)

	result := ""
	for _, line := range chunks {
		result = result + string(line) + "\n"
	}
	return result
}

// chunkSlice split slices
func chunkSlice(slice []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func (ts *Service) GetKeyID(appID string) (string, error) {
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

func (ts *Service) GetPublicKey(appID string) (interface{}, error) {
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

func (ts *Service) getPublicKeyFromPEM(appID, keysPath string) (interface{}, error) {
	// Construct the complete file path based on the AppID and provided keysPath
	filePath := fmt.Sprintf(publicKeyFilePathFormat, keysPath, appID)

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

func (ts *Service) GetUserID(ctx context.Context, appID string, key string) (string, error) {
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
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ts.GetPublicKey(appID)
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
