package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRefreshHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for request
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	// Get refresh jwtoken
	refreshToken := respReg.GetTokenData().GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	// Refresh tokens
	respRefresh, err := st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken,
		AppId:        appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respRefresh.GetTokenData())
}

func TestRefresh_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for request
	email := gofakeit.Email()
	password := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user
	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())
	require.NotEmpty(t, respReg.GetTokenData().GetRefreshToken())

	tests := []struct {
		name         string
		appID        int32
		userAgent    string
		ip           string
		refreshToken string
		expectedErr  error
	}{
		{
			name:         "Refresh with empty refresh jwtoken",
			appID:        appID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: "",
			expectedErr:  le.ErrRefreshTokenIsRequired,
		},
		{
			name:         "Refresh with empty appID",
			appID:        emptyAppID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: respReg.GetTokenData().GetRefreshToken(),
			expectedErr:  le.ErrAppIDIsRequired,
		},
		{
			name:         "Refresh with empty user agent",
			appID:        appID,
			userAgent:    "",
			ip:           ip,
			refreshToken: respReg.GetTokenData().GetRefreshToken(),
			expectedErr:  le.ErrUserAgentIsRequired,
		},
		{
			name:         "Refresh with empty IP",
			appID:        appID,
			userAgent:    userAgent,
			ip:           "",
			refreshToken: respReg.GetTokenData().GetRefreshToken(),
			expectedErr:  le.ErrIPIsRequired,
		},
		{
			name:         "Refresh when session not found",
			appID:        appID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: ksuid.New().String(),
			expectedErr:  le.ErrSessionNotFound,
		},
		{
			name:         "Refresh when device not found",
			appID:        appID,
			userAgent:    gofakeit.UserAgent(),
			ip:           ip,
			refreshToken: respReg.GetTokenData().GetRefreshToken(),
			expectedErr:  le.ErrUserDeviceNotFound,
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
}
