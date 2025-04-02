package api_tests

import (
	"testing"

	"github.com/rshelekhov/sso/internal/domain"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestGetUser_HappyPath(t *testing.T) {
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

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.User.GetEmail())
	require.NotEmpty(t, respGet.User.GetUpdatedAt())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}

func TestGetUserByID_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Register and login admin
	admin, cleanupAdmin := registerAndLoginAdmin(t, st, ctx)
	defer cleanupAdmin()

	// Register regular user
	regularEmail := gofakeit.Email()
	regularPass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

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

	// Try to get regular user's data using admin token
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respGet, err := st.AuthClient.GetUserByID(ctx, &ssov1.GetUserByIDRequest{
		UserId: regularUserID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.User.GetEmail())
	require.Equal(t, regularEmail, respGet.User.GetEmail())
	require.NotEmpty(t, respGet.User.GetUpdatedAt())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: regularToken,
	}
	cleanup(params, cfg.AppID)
}

func TestGetUser_UserNotFound(t *testing.T) {
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

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete user
	_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{})
	require.NoError(t, err)

	// Try to get user
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrUserNotFound.Error())
	require.Empty(t, respGet)
}

func TestGetUserByID_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	// Register and login admin
	admin, cleanupAdmin := registerAndLoginAdmin(t, st, ctx)
	defer cleanupAdmin()

	// Register regular user
	regularEmail := gofakeit.Email()
	regularPass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

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

	// Delete regular user
	_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{})
	require.NoError(t, err)

	// Try to get regular user's data using admin token
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respGet, err := st.AuthClient.GetUserByID(ctx, &ssov1.GetUserByIDRequest{
		UserId: regularUserID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.User.GetEmail())
	require.Equal(t, regularEmail, respGet.User.GetEmail())
	require.NotEmpty(t, respGet.User.GetUpdatedAt())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: regularToken,
	}
	cleanup(params, cfg.AppID)
}
