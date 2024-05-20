package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestLogoutHappyPath(t *testing.T) {
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

	// Get token and place it in metadata
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)
	require.NotEmpty(t, token.AccessToken)

	md := metadata.Pairs(token.AccessTokenKey, token.AccessToken)

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Logout user
	_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
		AppId: appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
}
