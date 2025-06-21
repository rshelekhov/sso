package api_tests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/entity"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
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

	// Request reset password instructions on email
	_, err = st.AuthService.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		Email:      email,
		ConfirmUrl: cfg.ConfirmChangePasswordURL,
	})
	require.NoError(t, err)

	// Get reset password token from storage to place it in request
	resetPasswordToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeResetPassword)
	require.NoError(t, err)

	// Change password
	_, err = st.AuthService.ChangePassword(ctx, &authv1.ChangePasswordRequest{
		Token:           resetPasswordToken,
		UpdatedPassword: randomFakePassword(),
	})
	require.NoError(t, err)

	// Cleanup database after test
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestResetPassword_TokenExpired(t *testing.T) {
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

	// Request reset password instructions on email
	_, err = st.AuthService.ResetPassword(ctx, &authv1.ResetPasswordRequest{
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
	_, err = st.AuthService.ChangePassword(ctx, &authv1.ChangePasswordRequest{
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
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestResetPassword_EmptyEmail(t *testing.T) {
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

	// Request reset password instructions on email
	_, err = st.AuthService.ResetPassword(ctx, &authv1.ResetPasswordRequest{
		Email:      emptyValue,
		ConfirmUrl: cfg.ConfirmChangePasswordURL,
	})
	require.Error(t, err)

	// Cleanup database after test
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestResetPassword_FailCasesWithPassword(t *testing.T) {
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
			_, err = st.AuthService.ResetPassword(ctx, &authv1.ResetPasswordRequest{
				Email:      email,
				ConfirmUrl: cfg.ConfirmChangePasswordURL,
			})
			require.NoError(t, err)

			// Get reset password token from storage to place it in request
			resetPasswordToken, err := st.Storage.GetToken(ctx, email, entity.TokenTypeResetPassword)
			require.NoError(t, err)

			// Change password
			_, err = st.AuthService.ChangePassword(ctx, &authv1.ChangePasswordRequest{
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
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}
