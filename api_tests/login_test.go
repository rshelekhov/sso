package api_tests

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"
)

func TestLoginHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
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

	// Login user
	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetTokenData())

	// Get token
	token := respLogin.GetTokenData()
	require.NotEmpty(t, token)

	// Get JWKS
	jwks, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
		AppId: appID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, jwks.GetJwks())

	jwk, err := getJWKByKid(jwks.GetJwks(), token.GetKid())
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

	loginTime := time.Now()

	// Parse the token using the public key
	tokenParsed, err := jwt.Parse(token.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, tokenParsed)

	// Check claims
	claims, ok := tokenParsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, issuer, claims[key.Issuer].(string))
	assert.Equal(t, email, claims[key.Email].(string))
	assert.Equal(t, appID, int32(claims[key.AppID].(float64)))

	const deltaSeconds = 1

	// Check if exp of token is in correct range, ttl get from st.Cfg.TokenTTL
	assert.InDelta(t, float64(loginTime.Add(st.Cfg.JWTAuth.AccessTokenTTL).Unix()), claims[key.ExpirationAt].(float64), deltaSeconds)
}

func getJWKByKid(jwks []*ssov1.JWK, kid string) (*ssov1.JWK, error) {
	for _, jwk := range jwks {
		if jwk.GetKid() == kid {
			return jwk, nil
		}
	}
	return nil, fmt.Errorf("JWK with kid %s not found", kid)
}

func TestLoginFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()

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
			name:        "Login with empty email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrEmailIsRequired,
		},
		{
			name:        "Login with empty password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrPasswordIsRequired,
		},
		{
			name:        "Login with empty appID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       0,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrAppIDIsRequired,
		},
		{
			name:        "Login with empty userAgent",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   "",
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrUserAgentIsRequired,
		},
		{
			name:        "Login with empty ip",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          "",
			expectedErr: le.ErrIPIsRequired,
		},
		{
			name:        "Login with both empty email and password",
			email:       "",
			password:    "",
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrEmailIsRequired,
		},
		{
			name:        "User not found",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrUserNotFound,
		},
		{
			name:        "Login with non-matching password",
			email:       email,
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.Email(),
			expectedErr: le.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var emailReg string
			if tt.name == "Login with non-matching password" {
				emailReg = email
			} else {
				emailReg = gofakeit.Email()
			}

			// Register user
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    emailReg,
				Password: randomFakePassword(),
				AppId:    appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: gofakeit.UserAgent(),
					Ip:        gofakeit.IPv4Address(),
				},
			})
			require.NoError(t, err)

			// Login user
			_, err = st.AuthClient.Login(ctx, &ssov1.LoginRequest{
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
