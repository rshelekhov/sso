package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestResetPassword_HappyPath(t *testing.T) {
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
		AppID:           cfg.AppID,
		VerificationURL: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Request reset password instructions on email
	_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
		Email:                    email,
		AppID:                    cfg.AppID,
		ConfirmChangePasswordURL: cfg.ConfirmChangePasswordURL,
	})
	require.NoError(t, err)

	// Get reset password token from storage to place it in request
	resetPasswordToken, err := st.Storage.GetToken(ctx, email, model.TokenTypeResetPassword)
	require.NoError(t, err)

	// Change password
	_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		ResetPasswordToken: resetPasswordToken,
		AppID:              cfg.AppID,
		UpdatedPassword:    randomFakePassword(),
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
	cleanup(params)
}

func TestResetPassword_TokenExpired(t *testing.T) {
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
		AppID:           cfg.AppID,
		VerificationURL: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Request reset password instructions on email
	_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
		Email:                    email,
		AppID:                    cfg.AppID,
		ConfirmChangePasswordURL: cfg.ConfirmChangePasswordURL,
	})
	require.NoError(t, err)

	// Set reset password token expired for test
	err = st.Storage.SetTokenExpired(ctx, email, model.TokenTypeResetPassword)
	require.NoError(t, err)

	// Get reset password token from storage to place it in request
	resetPasswordToken, err := st.Storage.GetToken(ctx, email, model.TokenTypeResetPassword)
	require.NoError(t, err)

	// Try to change password
	_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		ResetPasswordToken: resetPasswordToken,
		AppID:              cfg.AppID,
		UpdatedPassword:    randomFakePassword(),
	})
	require.Error(t, err)

	// Check that token expiration time more than current time
	tokenExp, err := st.Storage.GetTokenExpiresAt(ctx, email, model.TokenTypeResetPassword)
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
	cleanup(params)
}

func TestResetPassword_EmptyEmail(t *testing.T) {
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
		AppID:           cfg.AppID,
		VerificationURL: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	// Request reset password instructions on email
	_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
		Email:                    emptyValue,
		AppID:                    cfg.AppID,
		ConfirmChangePasswordURL: cfg.ConfirmChangePasswordURL,
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
	cleanup(params)
}

func TestResetPassword_FailCasesWithPassword(t *testing.T) {
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
		AppID:           cfg.AppID,
		VerificationURL: cfg.VerificationURL,
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
			expectedErr: le.ErrPasswordIsRequired,
		},
		{
			name:        "Change password when password is the same that old",
			password:    pass,
			expectedErr: le.ErrUpdatedPasswordMustNotMatchTheCurrent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Request reset password instructions on email
			_, err = st.AuthClient.ResetPassword(ctx, &ssov1.ResetPasswordRequest{
				Email:                    email,
				AppID:                    cfg.AppID,
				ConfirmChangePasswordURL: cfg.ConfirmChangePasswordURL,
			})
			require.NoError(t, err)

			// Get reset password token from storage to place it in request
			resetPasswordToken, err := st.Storage.GetToken(ctx, email, model.TokenTypeResetPassword)
			require.NoError(t, err)

			// Change password
			_, err = st.AuthClient.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
				ResetPasswordToken: resetPasswordToken,
				AppID:              cfg.AppID,
				UpdatedPassword:    tt.password,
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
	cleanup(params)
}
