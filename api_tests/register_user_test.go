package api_tests

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/rshelekhov/jwtauth"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt/v5"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestRegisterUser_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for request
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

	// Get JWKS
	jwks, err := st.AuthService.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, jwks.GetJwks())

	// Parse jwtoken
	tokenParsed, err := jwt.Parse(token.GetAccessToken(), func(token *jwt.Token) (any, error) {
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

func TestRegisterUser_DuplicatedRegistration(t *testing.T) {
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

	// Try to register again
	respDoubleReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.Error(t, err)
	assert.Empty(t, respDoubleReg.GetTokenData())
	assert.ErrorContains(t, err, domain.ErrUserAlreadyExists.Error())

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestRegisterUser_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

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
			name:        "Register with empty email",
			email:       emptyValue,
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: grpc.ErrEmailIsRequired,
		},
		{
			name:        "Register with empty password",
			email:       email,
			password:    emptyValue,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          ip,
			expectedErr: grpc.ErrPasswordIsRequired,
		},
		{
			name:        "Register with empty userAgent",
			email:       email,
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   emptyValue,
			ip:          ip,
			expectedErr: grpc.ErrUserAgentIsRequired,
		},
		{
			name:        "Register with empty ip",
			email:       email,
			password:    pass,
			clientID:    cfg.ClientID,
			userAgent:   userAgent,
			ip:          emptyValue,
			expectedErr: grpc.ErrIPIsRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Add clientID to gRPC metadata
			md := metadata.Pairs(clientid.Header, cfg.ClientID)
			ctx = metadata.NewOutgoingContext(ctx, md)

			// Register user
			_, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
				Email:           tt.email,
				Password:        tt.password,
				VerificationUrl: cfg.VerificationURL,
				UserDeviceData: &authv1.UserDeviceData{
					UserAgent: tt.userAgent,
					Ip:        tt.ip,
				},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}

func TestRegisterUser_UserAlreadyExists(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register first user
	resp1Reg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	token := resp1Reg.GetTokenData()
	require.NotEmpty(t, token)

	// Register second user
	resp2Reg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrUserAlreadyExists.Error())
	require.Empty(t, resp2Reg.GetTokenData())

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

// Test register new user using email with soft deleted user
func TestRegisterUser_UserSoftDeleted(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register first user
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

	// Get access token and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	// Create context for Delete User request
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete first user
	_, err = st.UserService.DeleteUser(ctx, &userv1.DeleteUserRequest{})
	require.NoError(t, err)

	// Register new user with the same email
	respReg, err = st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        randomFakePassword(),
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.NoError(t, err)

	token = respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}
