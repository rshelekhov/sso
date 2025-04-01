package api_tests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestVerifyEmail_HappyPath(t *testing.T) {
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

	// Get email verification token from storage to place it in request
	verificationToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeVerifyEmail)
	require.NoError(t, err)

	// Verify email
	_, err = st.AuthClient.VerifyEmail(ctx, &ssov1.VerifyEmailRequest{
		Token: verificationToken,
	})
	require.NoError(t, err)

	// Prepare data for get user request
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Get access and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	// Create context for Get user request
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user data to check if email was verified
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.User.GetVerified())
	require.True(t, respGet.User.GetVerified())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}

func TestVerifyEmail_TokenExpired(t *testing.T) {
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

	// Set verification token expired for test
	err = st.Storage.SetTokenExpired(ctx, email, entity.TokenTypeVerifyEmail)
	require.NoError(t, err)

	// Get email verification token from storage to place it in request
	verificationToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeVerifyEmail)
	require.NoError(t, err)

	// Try to verify email (a new email with verification token should be sent)
	_, err = st.AuthClient.VerifyEmail(ctx, &ssov1.VerifyEmailRequest{
		Token: verificationToken,
	})
	require.Error(t, err)

	// Check that token expiration time more than current time
	tokenExp, err := st.Storage.GetTokenExpiresAt(ctx, email, entity.TokenTypeVerifyEmail)
	require.NoError(t, err)
	require.True(t, tokenExp.After(time.Now()), "token expiration time should be after the current time")

	// Cleanup database after test
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}
