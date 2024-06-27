package api_tests

import (
	"crypto/rsa"
	"encoding/base64"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"math/big"
	"testing"
	"time"
)

func TestRegisterHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for request
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	// Get jwtoken
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Get JWKS
	jwks, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
		AppId: appID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, jwks.GetJwks())

	// Parse jwtoken
	tokenParsed, err := jwt.Parse(token.GetAccessToken(), func(token *jwt.Token) (interface{}, error) {
		kidRaw, ok := token.Header[jwtoken.Kid]
		require.True(t, ok)

		kid, ok := kidRaw.(string)
		require.True(t, ok)

		jwk, err := getJWKByKid(jwks.GetJwks(), kid)
		require.NoError(t, err)
		require.NotEmpty(t, jwk)

		n, err := base64.RawURLEncoding.DecodeString(jwk.GetN())
		require.NoError(t, err)

		e, err := base64.RawURLEncoding.DecodeString(jwk.GetE())
		require.NoError(t, err)

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}

		// Parse the jwtoken using the public key
		_, ok = token.Method.(*jwt.SigningMethodRSA)
		require.True(t, ok)

		return pubKey, nil
	})
	loginTime := time.Now()

	require.NoError(t, err)
	require.NotEmpty(t, tokenParsed)

	// Check claims
	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, issuer, claims[key.Issuer].(string))
	assert.Equal(t, email, claims[key.Email].(string))
	assert.Equal(t, appID, int32(claims[key.AppID].(float64)))

	const deltaSeconds = 1

	// Check if exp of jwtoken is in correct range, ttl get from st.Cfg.TokenTTL
	assert.InDelta(t, float64(loginTime.Add(st.Cfg.JWTAuth.AccessTokenTTL).Unix()), claims[key.ExpirationAt].(float64), deltaSeconds)
}

func TestRegisterDuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for request
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	// Try to register again
	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetTokenData())
	assert.ErrorContains(t, err, le.ErrUserAlreadyExists.Error())
}

func TestRegisterFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		userAgent   string
		ip          string
		expectedErr error
	}{
		{
			name:        "Register with empty email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrEmailIsRequired,
		},
		{
			name:        "Register with empty password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrPasswordIsRequired,
		},
		{
			name:        "Register with empty appID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrAppIDIsRequired,
		},
		{
			name:        "Register with empty userAgent",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   "",
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrUserAgentIsRequired,
		},
		{
			name:        "Register with empty ip",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          "",
			expectedErr: le.ErrIPIsRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register user
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgent,
					Ip:        tt.ip,
				},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}

func TestRegisterUserAlreadyExists(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()

	// Register first user
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: randomFakePassword(),
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	// Register second user
	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: randomFakePassword(),
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), le.ErrUserAlreadyExists.Error())
	require.Empty(t, respReg.GetTokenData())
}

// Test register new user using email with soft deleted user
func TestRegisterUserSoftDeleted(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register first user
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: randomFakePassword(),
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	// Get jwtoken and place it in metadata
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)
	require.NotEmpty(t, token.AccessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, token.AccessToken)

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete first user
	_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{
		AppId: appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Register second user
	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: randomFakePassword(),
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())
}
