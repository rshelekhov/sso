package token

import (
	"context"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

const (
	appID           = 1
	emptyAppID      = 0
	keysPath        = "./test_keys/"
	invalidKeysPath = "./invalid_test_keys/"
	invalidKey      = "invalidKey"
)

// ===========================================================================
//   Tests for NewAccessToken
// ===========================================================================

func TestNewAccessTokenHappyPath(t *testing.T) {
	ts := &Service{
		KeysPath: keysPath,
	}
	token, err := ts.NewAccessToken(appID, nil)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, token)
}

func TestNewAccessTokenFailCases(t *testing.T) {
	tests := []struct {
		name     string
		appID    int32
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
			token, err := ts.NewAccessToken(tt.appID, nil)
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
	ts := &Service{
		KeysPath: keysPath,
	}

	keyID, err := ts.GetKeyID(appID)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, keyID)
	require.NoError(t, err)
}

func TestGetKeyIDFailCases(t *testing.T) {
	tests := []struct {
		name     string
		appID    int32
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

func TestGetUserIDHappyPath(t *testing.T) {
	ts := &Service{
		KeysPath: keysPath,
	}

	userID := ksuid.New().String()

	claims := map[string]interface{}{
		key.UserID: userID,
	}

	token, err := ts.NewAccessToken(appID, claims)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, token)

	md := metadata.Pairs(key.Token, token)

	ctx := metadata.NewIncomingContext(context.Background(), md)

	uid, err := ts.GetUserID(ctx, appID, key.UserID)
	if err != nil {
		t.Errorf("Expected no error, but got %v", err)
	}
	require.NotEmpty(t, uid)
	require.Empty(t, err)
}

func TestGetUserIDFailCases(t *testing.T) {
	tests := []struct {
		name  string
		appID int32
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
			name:  "Empty token",
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
			ts := &Service{
				KeysPath: keysPath,
			}

			userID := ksuid.New().String()

			var token string
			if tt.token {
				claims := map[string]interface{}{
					tt.key: userID,
				}

				token, err := ts.NewAccessToken(appID, claims)
				if err != nil {
					t.Errorf("Expected no error, but got %v", err)
				}
				require.NotEmpty(t, token)
			}

			var md metadata.MD
			if tt.md {
				md = metadata.Pairs(key.Token, token)
			}

			ctx := metadata.NewIncomingContext(context.Background(), md)

			uid, err := ts.GetUserID(ctx, tt.appID, key.UserID)

			require.Empty(t, uid)
			require.Error(t, err)
		})
	}
}
