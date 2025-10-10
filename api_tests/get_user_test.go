package api_tests

import (
	"testing"

	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/pkg/jwtauth"

	"github.com/brianvoe/gofakeit/v6"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestGetUser_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	name := gofakeit.Name()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		Name:            name,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
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

	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user
	respGet, err := st.UserService.GetUser(ctx, &userv1.GetUserRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.User.GetEmail())
	require.NotEmpty(t, respGet.User.GetName())
	require.NotEmpty(t, respGet.User.GetUpdatedAt())

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestGetUserByID_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Register user
	email := gofakeit.Email()
	pass := randomFakePassword()
	name := gofakeit.Name()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		Name:            name,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	token := respReg.GetTokenData()
	accessToken := token.GetAccessToken()

	// Get user's ID
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respUser, err := st.UserService.GetUser(ctx, &userv1.GetUserRequest{})
	require.NoError(t, err)
	userID := respUser.GetUser().GetId()

	// Get user's data by ID
	respGet, err := st.UserService.GetUserByID(ctx, &userv1.GetUserByIDRequest{
		UserId: userID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.User.GetEmail())
	require.Equal(t, email, respGet.User.GetEmail())
	require.Equal(t, name, respGet.User.GetName())
	require.NotEmpty(t, respGet.User.GetUpdatedAt())

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestGetUser_UserNotFound(t *testing.T) {
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

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete user
	_, err = st.UserService.DeleteUser(ctx, &userv1.DeleteUserRequest{})
	require.NoError(t, err)

	// Try to get user
	respGet, err := st.UserService.GetUser(ctx, &userv1.GetUserRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrUserNotFound.Error())
	require.Empty(t, respGet)
}

func TestGetUserByID_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	// Register user
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

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
	require.NotEmpty(t, respReg.GetTokenData())

	token := respReg.GetTokenData()
	accessToken := token.GetAccessToken()

	// Get user's ID
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respUser, err := st.UserService.GetUser(ctx, &userv1.GetUserRequest{})
	require.NoError(t, err)
	userID := respUser.GetUser().GetId()

	// Delete user
	_, err = st.UserService.DeleteUser(ctx, &userv1.DeleteUserRequest{})
	require.NoError(t, err)

	// Try to get user's data by ID after deletion
	respGet, err := st.UserService.GetUserByID(ctx, &userv1.GetUserByIDRequest{
		UserId: userID,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrUserNotFound.Error())
	require.Empty(t, respGet)
}
