package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
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

	// Get access token and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md = metadata.Join(md, metadata.Pairs(jwtauth.AuthorizationHeader, accessToken))

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete user
	_, err = st.UserService.DeleteUser(ctx, &userv1.DeleteUserRequest{})
	require.NoError(t, err)
}

func TestDeleteUserByID_HappyPath(t *testing.T) {
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

	// Delete user by ID
	_, err = st.UserService.DeleteUserByID(ctx, &userv1.DeleteUserByIDRequest{
		UserId: userID,
	})
	require.NoError(t, err)
}
