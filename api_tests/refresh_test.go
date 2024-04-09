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

	// Get refresh token
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

func TestRefreshFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for request
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	tests := []struct {
		name     string
		email    string
		password string

		appIDForRegister int32
		appIDForRefresh  int32

		userAgentForRegister string
		userAgentForRefresh  string

		ipForRegister string
		ipForRefresh  string

		expectedErr error
	}{
		{
			name:                 "Refresh with empty refresh token",
			email:                gofakeit.Email(),
			password:             randomFakePassword(),
			appIDForRegister:     appID,
			appIDForRefresh:      appID,
			userAgentForRegister: userAgent,
			userAgentForRefresh:  userAgent,
			ipForRegister:        ip,
			ipForRefresh:         ip,
			expectedErr:          le.ErrRefreshTokenIsRequired,
		},
		{
			name:                 "Refresh with empty appID",
			email:                gofakeit.Email(),
			password:             randomFakePassword(),
			appIDForRegister:     appID,
			appIDForRefresh:      emptyAppID,
			userAgentForRegister: userAgent,
			userAgentForRefresh:  userAgent,
			ipForRegister:        ip,
			ipForRefresh:         ip,
			expectedErr:          le.ErrAppIDIsRequired,
		},
		{
			name:                 "Refresh with empty user agent",
			email:                gofakeit.Email(),
			password:             randomFakePassword(),
			appIDForRegister:     appID,
			appIDForRefresh:      appID,
			userAgentForRegister: userAgent,
			userAgentForRefresh:  "",
			ipForRegister:        ip,
			ipForRefresh:         ip,
			expectedErr:          le.ErrUserAgentIsRequired,
		},
		{
			name:                 "Refresh with empty IP",
			email:                gofakeit.Email(),
			password:             randomFakePassword(),
			appIDForRegister:     appID,
			appIDForRefresh:      appID,
			userAgentForRegister: userAgent,
			userAgentForRefresh:  userAgent,
			ipForRegister:        ip,
			ipForRefresh:         "",
			expectedErr:          le.ErrIPIsRequired,
		},
		{
			name:                 "Refresh when session not found",
			email:                gofakeit.Email(),
			password:             randomFakePassword(),
			appIDForRegister:     appID,
			appIDForRefresh:      appID,
			userAgentForRegister: userAgent,
			userAgentForRefresh:  userAgent,
			ipForRegister:        ip,
			ipForRefresh:         ip,
			expectedErr:          le.ErrSessionNotFound,
		},
		{
			name:                 "Refresh when device not found",
			email:                gofakeit.Email(),
			password:             randomFakePassword(),
			appIDForRegister:     appID,
			appIDForRefresh:      appID,
			userAgentForRegister: userAgent,
			userAgentForRefresh:  gofakeit.UserAgent(),
			ipForRegister:        ip,
			ipForRefresh:         ip,
			expectedErr:          le.ErrUserDeviceNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Register user
			respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appIDForRegister,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgentForRegister,
					Ip:        tt.ipForRegister,
				},
			})
			require.NoError(t, err)
			require.NotEmpty(t, respReg.GetTokenData())

			var refreshToken string

			// Get refresh token
			if tt.name == "Refresh with empty refresh token" {
				refreshToken = ""
			} else if tt.name == "Refresh when session not found" {
				refreshToken = ksuid.New().String()
			} else {
				refreshToken = respReg.GetTokenData().GetRefreshToken()
				require.NotEmpty(t, refreshToken)
			}

			// Refresh tokens
			_, err = st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
				RefreshToken: refreshToken,
				AppId:        tt.appIDForRefresh,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgentForRefresh,
					Ip:        tt.ipForRefresh,
				},
			})

			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}
