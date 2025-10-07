package api_tests

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestLogin_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	registerUserID := respReg.GetUserId()
	require.NotEmpty(t, registerUserID)

	require.NotEmpty(t, respReg.GetTokenData())

	// Login user
	respLogin, err := st.AuthService.Login(ctx, &authv1.LoginRequest{
		Email:    email,
		Password: pass,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	loginUserID := respLogin.GetUserId()
	require.NotEmpty(t, loginUserID)
	require.Equal(t, registerUserID, loginUserID)

	token := respLogin.GetTokenData()
	require.NotEmpty(t, token)

	// Get JWKS
	jwks, err := st.AuthService.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, jwks.GetJwks())

	// Parse jwtoken
	tokenParsed, err := jwt.Parse(token.GetAccessToken(), func(token *jwt.Token) (interface{}, error) {
		kidRaw, ok := token.Header[domain.KIDKey]
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

	assert.Equal(t, cfg.Issuer, claims[domain.IssuerKey].(string))
	assert.Equal(t, cfg.ClientID, claims[domain.ClientIDKey].(string))

	const deltaSeconds = 1

	// Check if exp of jwtoken is in correct range, ttl get from st.Cfg.TokenTTL
	assert.InDelta(t, float64(loginTime.Add(st.Cfg.JWT.AccessTokenTTL).Unix()), claims[domain.ExpirationAtKey].(float64), deltaSeconds)

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func getJWKByKid(jwks []*authv1.JWK, kid string) (*authv1.JWK, error) {
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

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
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
		clientID    string
		userAgent   string
		ip          string
		expectedErr error
	}{
		{
			name:        "Login with empty email",
			email:       emptyValue,
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: grpc.ErrEmailIsRequired,
		},
		{
			name:        "Login with empty password",
			email:       email,
			password:    emptyValue,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: grpc.ErrPasswordIsRequired,
		},
		{
			name:        "Login with empty userAgent",
			email:       email,
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   emptyValue,
			ip:          ip,
			expectedErr: grpc.ErrUserAgentIsRequired,
		},
		{
			name:        "Login with empty IP",
			email:       email,
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          emptyValue,
			expectedErr: grpc.ErrIPIsRequired,
		},
		{
			name:        "Login with both empty email and password",
			email:       emptyValue,
			password:    emptyValue,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: grpc.ErrEmailIsRequired,
		},
		{
			name:        "User not found",
			email:       gofakeit.Email(),
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: domain.ErrUserNotFound,
		},
		{
			name:        "Login with non-matching password",
			email:       email,
			password:    randomFakePassword(),
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: domain.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Login user
			_, err := st.AuthService.Login(ctx, &authv1.LoginRequest{
				Email:    tt.email,
				Password: tt.password,
				UserDeviceData: &authv1.UserDeviceData{
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
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}
