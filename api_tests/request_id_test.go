package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/pkg/middleware/requestid"
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
	md := metadata.Pairs()
	md.Append(requestid.HeaderKey, "requestID #1 from the client side")

	// Create context with metadata
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
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

	md = metadata.Pairs(jwtauth.AccessTokenHeader, accessToken)

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Logout user
	_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}

func TestRequestID_EmptyRequestID(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Create metadata
	md := metadata.Pairs()
	md.Append(requestid.HeaderKey, emptyValue)

	// Create context with metadata
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
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

	md = metadata.Pairs(jwtauth.AccessTokenKey, accessToken)
	md.Append(requestid.HeaderKey, emptyValue)

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Logout user
	_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}
