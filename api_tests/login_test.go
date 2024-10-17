package api_tests

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"
)

func TestLogin_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user
	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		AppId:           cfg.AppID,
		VerificationUrl: cfg.VerificationURL,
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
		AppId:    cfg.AppID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	token := respLogin.GetTokenData()
	require.NotEmpty(t, token)

	// Get JWKS
	jwks, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
		AppId: cfg.AppID,
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

	assert.Equal(t, cfg.Issuer, claims[key.Issuer].(string))
	assert.Equal(t, email, claims[key.Email].(string))
	assert.Equal(t, cfg.AppID, claims[key.AppID].(string))

	const deltaSeconds = 1

	// Check if exp of jwtoken is in correct range, ttl get from st.Cfg.TokenTTL
	assert.InDelta(t, float64(loginTime.Add(st.Cfg.JWTAuth.AccessTokenTTL).Unix()), claims[key.ExpirationAt].(float64), deltaSeconds)

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}

func getJWKByKid(jwks []*ssov1.JWK, kid string) (*ssov1.JWK, error) {
	for _, jwk := range jwks {
		if jwk.GetKid() == kid {
			return jwk, nil
		}
	}
	return nil, fmt.Errorf("JWK with kid %s not found", kid)
}

func TestLogin_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user
	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		AppId:           cfg.AppID,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       string
		userAgent   string
		ip          string
		expectedErr error
	}{
		{
			name:        "Login with empty email",
			email:       emptyValue,
			password:    pass,
			appID:       cfg.AppID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: le.ErrEmailIsRequired,
		},
		{
			name:        "Login with empty password",
			email:       email,
			password:    emptyValue,
			appID:       cfg.AppID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: le.ErrPasswordIsRequired,
		},
		{
			name:        "Login with empty appID",
			email:       email,
			password:    pass,
			appID:       emptyValue,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: le.ErrAppIDIsRequired,
		},
		{
			name:        "Login with empty userAgent",
			email:       email,
			password:    pass,
			appID:       cfg.AppID,
			userAgent:   emptyValue,
			ip:          ip,
			expectedErr: le.ErrUserAgentIsRequired,
		},
		{
			name:        "Login with empty IP",
			email:       email,
			password:    pass,
			appID:       cfg.AppID,
			userAgent:   userAgent,
			ip:          emptyValue,
			expectedErr: le.ErrIPIsRequired,
		},
		{
			name:        "Login with both empty email and password",
			email:       emptyValue,
			password:    emptyValue,
			appID:       cfg.AppID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: le.ErrEmailIsRequired,
		},
		{
			name:        "User not found",
			email:       gofakeit.Email(),
			password:    pass,
			appID:       cfg.AppID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: le.ErrUserNotFound,
		},
		{
			name:        "Login with non-matching password",
			email:       email,
			password:    randomFakePassword(),
			appID:       cfg.AppID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: le.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Login user
			_, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
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

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}
