package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestDeleteUser_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add appID to gRPC metadata
	md := metadata.Pairs(appid.Header, cfg.AppID)
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

	md = metadata.Join(md, metadata.Pairs(jwtauth.AuthorizationHeader, accessToken))

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete user
	_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{})
	require.NoError(t, err)
}

func TestDeleteUserByID_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Register admin user via CLI
	adminEmail := gofakeit.Email()
	adminPass := randomFakePassword()

	err := registerAdmin(t, cfg.AppID, adminEmail, adminPass)
	require.NoError(t, err)

	// Login as admin
	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Email:    adminEmail,
		Password: adminPass,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        gofakeit.IPv4Address(),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respLogin.GetTokenData())

	adminToken := respLogin.GetTokenData()
	adminAccessToken := adminToken.GetAccessToken()

	// Register regular user
	regularEmail := gofakeit.Email()
	regularPass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           regularEmail,
		Password:        regularPass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	regularToken := respReg.GetTokenData()
	regularAccessToken := regularToken.GetAccessToken()

	// Get regular user's ID
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, regularAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respUser, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)
	regularUserID := respUser.GetUser().GetId()

	// Try to delete regular user's data using admin token
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, adminAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err = st.AuthClient.DeleteUserByID(ctx, &ssov1.DeleteUserByIDRequest{
		UserId: regularUserID,
	})
	require.NoError(t, err)

	// Cleanup admin
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, adminAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{})
	require.NoError(t, err)
}
