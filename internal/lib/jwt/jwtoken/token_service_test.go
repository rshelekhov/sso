package jwtoken

import (
	"context"
	"fmt"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"os"
	"path/filepath"
	"testing"
)

const (
	appID           = "test-app-id"
	emptyAppID      = ""
	keysPath        = "./test_keys/"
	invalidKeysPath = "./invalid_test_keys/"
	invalidKey      = "invalidKey"
)

var (
	privateKeyFilePath = filepath.Join(keysPath, fmt.Sprintf("app_%s_private.pem", appID))
	publicKeyFilePath  = filepath.Join(keysPath, fmt.Sprintf("app_%s_public.pem", appID))
)

// ===========================================================================
//   Tests for GeneratePEMKeyPair
// ===========================================================================

func TestGeneratePEMKeyPair_HappyPath(t *testing.T) {
	// Ensure the keysPath directory exists
	createTestDir(t, keysPath)

	// Cleanup the directory after test
	defer removeTestDir(t, keysPath)

	ts := &Service{
		KeysPath: keysPath,
	}

	err := ts.GeneratePEMKeyPair(appID)
	if err != nil {
		t.Fatalf("Failed to generate PEM key pair: %v", err)
	}

	// Check if the files were created
	if _, err = os.Stat(privateKeyFilePath); os.IsNotExist(err) {
		t.Errorf("Failed to create private key file: %v", err)
	}

	if _, err = os.Stat(publicKeyFilePath); os.IsNotExist(err) {
		t.Errorf("Failed to create public key file: %v", err)
	}
}

// ===========================================================================
//   Tests for NewAccessToken
// ===========================================================================

func TestNewAccessToken_HappyPath(t *testing.T) {
	// Ensure the keysPath directory exists
	createTestDir(t, keysPath)

	// Cleanup the directory after test
	defer removeTestDir(t, keysPath)

	ts := &Service{
		KeysPath: keysPath,
	}

	err := ts.GeneratePEMKeyPair(appID)
	if err != nil {
		t.Fatalf("Failed to generate PEM key pair: %v", err)
	}

	keyID, err := ts.GetKeyID(appID)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, keyID)
	require.NoError(t, err)

	token, err := ts.NewAccessToken(appID, keyID, nil)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, token)
}

func TestNewAccessToken_FailCases(t *testing.T) {
	tests := []struct {
		name     string
		appID    string
		keysPath string
	}{
		{
			name:     "Invalid appID",
			appID:    emptyAppID,
			keysPath: keysPath,
		},
		{
			name:     "Invalid keysPath",
			appID:    appID,
			keysPath: invalidKeysPath,
		},
		{
			name:     "Empty keysPath",
			appID:    appID,
			keysPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &Service{
				KeysPath: tt.keysPath,
			}

			keyID, _ := ts.GetKeyID(appID)

			token, err := ts.NewAccessToken(tt.appID, keyID, nil)
			if err == nil {
				t.Error("Expected an error, but got nil")
			}
			require.Empty(t, token)
			require.Error(t, err)
		})
	}
}

// ===========================================================================
//   Tests for GetKeyID
// ===========================================================================

func TestGetKeyID(t *testing.T) {
	// Ensure the keysPath directory exists
	createTestDir(t, keysPath)

	// Cleanup the directory after test
	defer removeTestDir(t, keysPath)

	ts := &Service{
		KeysPath: keysPath,
	}

	err := ts.GeneratePEMKeyPair(appID)
	if err != nil {
		t.Fatalf("Failed to generate PEM key pair: %v", err)
	}

	keyID, err := ts.GetKeyID(appID)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, keyID)
	require.NoError(t, err)
}

func TestGetKeyID_FailCases(t *testing.T) {
	tests := []struct {
		name     string
		appID    string
		keysPath string
	}{
		{
			name:     "Invalid appID and valid keysPath",
			appID:    emptyAppID,
			keysPath: keysPath,
		},
		{
			name:     "Valid appID and invalid keysPath",
			appID:    appID,
			keysPath: invalidKeysPath,
		},
		{
			name:     "Invalid appID and invalid keysPath",
			appID:    emptyAppID,
			keysPath: invalidKeysPath,
		},
		{
			name:     "Valid appID and empty keysPath",
			appID:    appID,
			keysPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &Service{
				KeysPath: tt.keysPath,
			}
			keyID, err := ts.GetKeyID(tt.appID)
			require.Empty(t, keyID)
			require.Error(t, err)
		})
	}
}

// ===========================================================================
//   Tests for GetUserID
// ===========================================================================

func TestGetUserID_HappyPath(t *testing.T) {
	// Ensure the keysPath directory exists
	createTestDir(t, keysPath)

	// Cleanup the directory after test
	defer removeTestDir(t, keysPath)

	ts := &Service{
		KeysPath: keysPath,
	}

	err := ts.GeneratePEMKeyPair(appID)
	if err != nil {
		t.Fatalf("Failed to generate PEM key pair: %v", err)
	}

	userID := ksuid.New().String()

	claims := map[string]interface{}{
		key.UserID: userID,
	}

	keyID, err := ts.GetKeyID(appID)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, keyID)
	require.NoError(t, err)

	token, err := ts.NewAccessToken(appID, keyID, claims)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, token)

	md := metadata.Pairs(AccessTokenKey, token)

	ctx := metadata.NewIncomingContext(context.Background(), md)

	uid, err := ts.GetUserID(ctx, appID, key.UserID)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, uid)
	require.Empty(t, err)
}

func TestGetUserID_FailCases(t *testing.T) {
	tests := []struct {
		name  string
		appID string
		key   string
		token bool
		md    bool
	}{
		{
			name:  "Invalid appID and valid key",
			appID: emptyAppID,
			key:   key.UserID,
			token: true,
			md:    true,
		},
		{
			name:  "Valid appID and invalid key",
			appID: appID,
			key:   invalidKey,
			token: true,
			md:    true,
		},
		{
			name:  "Invalid appID and invalid key",
			appID: emptyAppID,
			key:   invalidKey,
			token: true,
			md:    true,
		},
		{
			name:  "Empty jwtoken",
			appID: appID,
			key:   key.UserID,
			token: false,
			md:    true,
		},
		{
			name:  "Empty metadata",
			appID: appID,
			key:   key.UserID,
			token: true,
			md:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure the keysPath directory exists
			createTestDir(t, keysPath)

			// Cleanup the directory after test
			defer removeTestDir(t, keysPath)

			ts := &Service{
				KeysPath: keysPath,
			}

			err := ts.GeneratePEMKeyPair(appID)
			if err != nil {
				t.Fatalf("Failed to generate PEM key pair: %v", err)
			}

			userID := ksuid.New().String()

			var token string
			if tt.token {
				claims := map[string]interface{}{
					tt.key: userID,
				}

				keyID, err := ts.GetKeyID(appID)
				if err != nil {
					t.Errorf("Expected no error, but got %v", err)
				}
				require.NotEmpty(t, keyID)
				require.NoError(t, err)

				token, err := ts.NewAccessToken(appID, keyID, claims)
				if err != nil {
					t.Errorf("Expected no error, but got %v", err)
				}
				require.NotEmpty(t, token)
			}

			var md metadata.MD
			if tt.md {
				md = metadata.Pairs(AccessTokenKey, token)
			}

			ctx := metadata.NewIncomingContext(context.Background(), md)

			uid, err := ts.GetUserID(ctx, tt.appID, key.UserID)

			require.Empty(t, uid)
			require.Error(t, err)
		})
	}
}

// ===========================================================================
//   Helper functions
// ===========================================================================

func createTestDir(t *testing.T, dir string) {
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
}

func removeTestDir(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("Failed to remove directory: %v", err)
	}
}
