package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRefresh_HappyPath(t *testing.T) {
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

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Get refresh jwtoken
	refreshToken := token.GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	// Refresh tokens
	respRefresh, err := st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken,
		AppId:        cfg.AppID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respRefresh.GetTokenData())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}

func TestRefresh_FailCases(t *testing.T) {
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

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	refreshToken := token.GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	tests := []struct {
		name         string
		appID        string
		userAgent    string
		ip           string
		refreshToken string
		expectedErr  error
	}{
		{
			name:         "Refresh with empty appID",
			appID:        emptyValue,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: respReg.GetTokenData().GetRefreshToken(),
			expectedErr:  le.ErrAppIDIsRequired,
		},
		{
			name:         "Refresh with empty user agent",
			appID:        cfg.AppID,
			userAgent:    emptyValue,
			ip:           ip,
			refreshToken: refreshToken,
			expectedErr:  le.ErrUserAgentIsRequired,
		},
		{
			name:         "Refresh with empty IP",
			appID:        cfg.AppID,
			userAgent:    userAgent,
			ip:           emptyValue,
			refreshToken: refreshToken,
			expectedErr:  le.ErrIPIsRequired,
		},
		{
			name:         "Refresh with empty refresh jwtoken",
			appID:        cfg.AppID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: emptyValue,
			expectedErr:  le.ErrRefreshTokenIsRequired,
		},
		{
			name:         "Refresh when session not found",
			appID:        cfg.AppID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: ksuid.New().String(),
			expectedErr:  le.ErrSessionNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Refresh tokens
			_, err = st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
				RefreshToken: tt.refreshToken,
				AppId:        tt.appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgent,
					Ip:        tt.ip,
				},
			})

			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}

func TestRefresh_DeviceNotFound(t *testing.T) {
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

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	refreshToken := token.GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	// Refresh tokens
	_, err = st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken,
		AppId:        cfg.AppID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        ip,
		},
	})

	require.Contains(t, err.Error(), le.ErrUserDeviceNotFound.Error())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}
