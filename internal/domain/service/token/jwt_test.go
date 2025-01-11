package token

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/token/mocks"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestToken_NewAccessToken(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	claimKey := "user_id"
	claimValue := "test-user-id"
	additionalClaims := map[string]interface{}{
		claimKey: claimValue,
	}

	tests := []struct {
		name          string
		appID         string
		kid           string
		claims        map[string]interface{}
		mockBehavior  func(mockKeyStorage *mocks.KeyStorage)
		validateToken bool
		expectedError error
	}{
		{
			name:   "Success",
			appID:  appID,
			kid:    "test-kid",
			claims: additionalClaims,
			mockBehavior: func(mockKeyStorage *mocks.KeyStorage) {
				mockKeyStorage.EXPECT().
					GetPrivateKey(appID).
					Once().
					Return(privateKeyPEM, nil)
			},
			validateToken: true,
			expectedError: nil,
		},
		{
			name:          "Empty appID",
			appID:         "",
			kid:           "test-kid",
			claims:        additionalClaims,
			mockBehavior:  func(mockKeyStorage *mocks.KeyStorage) {},
			expectedError: domain.ErrAppIDIsNotAllowed,
		},
		{
			name:          "Empty kid",
			appID:         appID,
			kid:           "",
			claims:        additionalClaims,
			mockBehavior:  func(mockKeyStorage *mocks.KeyStorage) {},
			expectedError: domain.ErrEmptyKidIsNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior(mockKeyStorage)

			tokenString, err := tokenService.NewAccessToken(tt.appID, tt.kid, tt.claims)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, tokenString)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, tokenString)

			if tt.validateToken {
				token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return &privateKey.PublicKey, nil
				})
				require.NoError(t, err)
				require.True(t, token.Valid)

				claims := token.Claims.(jwt.MapClaims)
				require.Equal(t, claimValue, claims[claimKey])
				require.Equal(t, tt.kid, token.Header["kid"])
			}
		})
	}
}

func TestToken_GetKeyID(t *testing.T) {
	mockKeyStorage, tokenService, privateKey, privateKeyPEM := setup(t)

	tests := []struct {
		name          string
		appID         string
		mockBehavior  func(mockKeyStorage *mocks.KeyStorage)
		expectedKID   string
		expectedError error
	}{
		{
			name:  "Success",
			appID: appID,
			mockBehavior: func(mockKeyStorage *mocks.KeyStorage) {
				mockKeyStorage.EXPECT().
					GetPrivateKey(appID).
					Once().
					Return(privateKeyPEM, nil)
			},
			expectedKID: func() string {
				publicKey := &privateKey.PublicKey
				der, err := x509.MarshalPKIXPublicKey(publicKey)
				if err != nil {
					t.Fatal(err)
				}
				s := sha1.Sum(der)
				return base64.URLEncoding.EncodeToString(s[:])
			}(),
			expectedError: nil,
		},
		{
			name:          "Empty appID",
			appID:         "",
			mockBehavior:  func(mockKeyStorage *mocks.KeyStorage) {},
			expectedKID:   "",
			expectedError: domain.ErrAppIDIsNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior(mockKeyStorage)

			keyID, err := tokenService.Kid(tt.appID)

			if tt.expectedError != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedError)
				require.Empty(t, keyID)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedKID, keyID)
			}
		})
	}
}
