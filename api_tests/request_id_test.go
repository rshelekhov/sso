package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/internal/lib/interceptor/requestid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestRequestID_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Create metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(requestid.Header, "requestID #1 from the client side")

	// Create context with metadata
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

	// Get access token and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	// Create context for Logout request
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Logout user
	_, err = st.AuthService.Logout(ctx, &authv1.LogoutRequest{
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestRequestID_EmptyRequestID(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Create metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(requestid.Header, emptyValue)

	// Create context with metadata
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

	// Get access token and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	// Create context for Logout request
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	md.Append(requestid.Header, emptyValue)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Logout user
	_, err = st.AuthService.Logout(ctx, &authv1.LogoutRequest{
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}
