package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestGetUser_HappyPath(t *testing.T) {
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
		VerificationURL: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{
		AppId: cfg.AppID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.GetEmail())
	require.NotEmpty(t, respGet.GetUpdatedAt())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}

func TestGetUser_EmptyAppID(t *testing.T) {
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
		VerificationURL: cfg.VerificationURL,
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

	md := metadata.Pairs(jwtoken.AccessTokenKey, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user
	_, err = st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{
		AppId: emptyValue,
	})

	require.Contains(t, err.Error(), le.ErrAppIDIsRequired.Error())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}
