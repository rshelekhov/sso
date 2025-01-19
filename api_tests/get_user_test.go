package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"

	// "github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
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

	// Add appID to gRPC metadata
	md := metadata.Pairs()
	md.Append(appid.HeaderKey, cfg.AppID)
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

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md = metadata.Pairs(jwtauth.AccessTokenHeader, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
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
	cleanup(params, cfg.AppID)
}
