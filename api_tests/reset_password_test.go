package api_tests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestResetPassword_HappyPath(t *testing.T) {
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

	// Request reset password instructions on email
	_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
		Email:      email,
		ConfirmUrl: cfg.ConfirmChangePasswordURL,
	})
	require.NoError(t, err)

	// Get reset password token from storage to place it in request
	resetPasswordToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeResetPassword)
	require.NoError(t, err)

	// Change password
	_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		Token:           resetPasswordToken,
		UpdatedPassword: randomFakePassword(),
	})
	require.NoError(t, err)

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

func TestResetPassword_TokenExpired(t *testing.T) {
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

	// Request reset password instructions on email
	_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
		Email:      email,
		ConfirmUrl: cfg.ConfirmChangePasswordURL,
	})
	require.NoError(t, err)

	// Set reset password token expired for test
	err = st.Storage.SetTokenExpired(ctx, email, entity.TokenTypeResetPassword)
	require.NoError(t, err)

	// Get reset password token from storage to place it in request
	resetPasswordToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeResetPassword)
	require.NoError(t, err)

	// Try to change password
	_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		Token:           resetPasswordToken,
		UpdatedPassword: randomFakePassword(),
	})
	require.Error(t, err)

	// Check that token expiration time more than current time
	tokenExp, err := st.Storage.GetTokenExpiresAt(ctx, email, entity.TokenTypeResetPassword)
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

func TestResetPassword_EmptyEmail(t *testing.T) {
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

	// Request reset password instructions on email
	_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
		Email:      emptyValue,
		ConfirmUrl: cfg.ConfirmChangePasswordURL,
	})
	require.Error(t, err)

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

func TestResetPassword_FailCasesWithPassword(t *testing.T) {
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

	tests := []struct {
		name        string
		password    string
		expectedErr error
	}{
		{
			name:        "Change password with empty password",
			password:    emptyValue,
			expectedErr: grpc.ErrPasswordIsRequired,
		},
		{
			name:        "Change password when password is the same that old",
			password:    pass,
			expectedErr: domain.ErrNoPasswordChangesDetected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Request reset password instructions on email
			_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
				Email:      email,
				ConfirmUrl: cfg.ConfirmChangePasswordURL,
			})
			require.NoError(t, err)

			// Get reset password token from storage to place it in request
			resetPasswordToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeResetPassword)
			require.NoError(t, err)

			// Change password
			_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
				Token:           resetPasswordToken,
				UpdatedPassword: tt.password,
			})
			require.Error(t, tt.expectedErr)
		})
	}

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
