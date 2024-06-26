package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestGetUserHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
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

	// Get jwtoken and place it in metadata
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)
	require.NotEmpty(t, token.AccessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, token.AccessToken)

	// Create context for the request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Get user
	respGet, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{
		AppId: appID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, respGet.GetEmail())
	require.NotEmpty(t, respGet.GetUpdatedAt())
}

func TestGetUserFailCases(t *testing.T) {
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
			name:        "Get user with empty appID",
			email:       gofakeit.Email(),
			password:    randomFakePassword(),
			appID:       emptyAppID,
			userAgent:   gofakeit.UserAgent(),
			ip:          gofakeit.IPv4Address(),
			expectedErr: le.ErrAppIDIsRequired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Register user
			respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tc.email,
				Password: tc.password,
				AppId:    appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tc.userAgent,
					Ip:        tc.ip,
				},
			})
			require.NoError(t, err)
			require.NotEmpty(t, respReg.GetTokenData())

			// Get jwtoken and place it in metadata
			token := respReg.GetTokenData()
			require.NotEmpty(t, token)
			require.NotEmpty(t, token.AccessToken)

			md := metadata.Pairs(jwtoken.AccessTokenKey, token.AccessToken)

			// Create context for the request
			ctx = metadata.NewOutgoingContext(ctx, md)

			// Get user
			_, err = st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{
				AppId: tc.appID,
			})

			require.Contains(t, err.Error(), tc.expectedErr.Error())
		})
	}
}
