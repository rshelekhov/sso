package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestRefresh_HappyPath(t *testing.T) {
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

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	// Get refresh jwtoken
	refreshToken := token.GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	// Refresh tokens
	respRefresh, err := st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken,
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
	cleanup(params, cfg.AppID)
}

func TestRefresh_FailCases(t *testing.T) {
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
			name:         "Refresh with empty user agent",
			appID:        cfg.AppID,
			userAgent:    emptyValue,
			ip:           ip,
			refreshToken: refreshToken,
			expectedErr:  grpc.ErrUserAgentIsRequired,
		},
		{
			name:         "Refresh with empty IP",
			appID:        cfg.AppID,
			userAgent:    userAgent,
			ip:           emptyValue,
			refreshToken: refreshToken,
			expectedErr:  grpc.ErrIPIsRequired,
		},
		{
			name:         "Refresh with empty refresh jwtoken",
			appID:        cfg.AppID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: emptyValue,
			expectedErr:  grpc.ErrRefreshTokenIsRequired,
		},
		{
			name:         "Refresh when session not found",
			appID:        cfg.AppID,
			userAgent:    userAgent,
			ip:           ip,
			refreshToken: ksuid.New().String(),
			expectedErr:  domain.ErrSessionNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Refresh tokens
			_, err = st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
				RefreshToken: tt.refreshToken,
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
	cleanup(params, cfg.AppID)
}

func TestRefresh_DeviceNotFound(t *testing.T) {
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

	token := respReg.GetTokenData()
	require.NotEmpty(t, token)

	refreshToken := token.GetRefreshToken()
	require.NotEmpty(t, refreshToken)

	// Refresh tokens
	_, err = st.AuthClient.Refresh(ctx, &ssov1.RefreshRequest{
		RefreshToken: refreshToken,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: gofakeit.UserAgent(),
			Ip:        ip,
		},
	})

	require.Error(t, err)
	// require.Contains(t, err.Error(), domain.ErrUserDeviceNotFound.Error())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}
