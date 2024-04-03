package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegisterHappyPath(t *testing.T) {
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
}

func TestRegisterDuplicatedRegistration(t *testing.T) {
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

	// Try to register again
	respReg, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Password: pass,
		AppId:    appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.Error(t, err)
	assert.Empty(t, respReg.GetTokenData())
	assert.ErrorContains(t, err, le.ErrUserAlreadyExists.Error())
}

func TestRegisterFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		email       string
		password    string
		appID       int32
		userAgent   string
		ip          string
		expectedErr error
	}{
		{
			name:        "Register with empty email",
			email:       "",
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrEmailIsRequired,
		},
		{
			name:        "Register with empty password",
			email:       gofakeit.Email(),
			password:    "",
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrPasswordIsRequired,
		},
		{
			name:        "Register with empty appID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrAppIDIsRequired,
		},
		{
			name:        "Register with empty userAgent",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   "",
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrUserAgentIsRequired,
		},
		{
			name:        "Register with empty ip",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       appID,
			userAgent:   gofakeit.UserAgent(),
			ip:          "",
			expectedErr: le.ErrIPIsRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register user
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.email,
				Password: tt.password,
				AppId:    tt.appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgent,
					Ip:        tt.ip,
				},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}
