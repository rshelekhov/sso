package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestVerifyEmail_HappyPath(t *testing.T) {
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

	// Get email verification token from storage to place it in request
	verificationToken, err := st.Storage.GetVerificationToken(ctx, email)
	require.NoError(t, err)

	// Verify email
	_, err = st.AuthClient.VerifyEmail(ctx, &ssov1.VerifyEmailRequest{
		VerificationToken: verificationToken,
	})
	require.NoError(t, err)

	// Prepare data for get user request
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, accessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user data to check if email was verified
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{
		AppId: cfg.AppID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.GetVerified())
	require.True(t, respGet.GetVerified())
}
