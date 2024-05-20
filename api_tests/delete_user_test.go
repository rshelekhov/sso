package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestDeleteUserHappyPath(t *testing.T) {
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

	// Get token and place it in metadata
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)
	require.NotEmpty(t, token.AccessToken)

	md := metadata.Pairs(token.AccessTokenKey, token.AccessToken)

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Delete user
	_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{
		AppId: appID,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
}

func TestDeleteUserFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	tests := []struct {
		name         string
		appID        int32
		userAgentReg string
		userAgentDel string
		ipReg        string
		ipDel        string
		expectedErr  error
	}{
		{
			name:         "Delete user with empty appID",
			appID:        emptyAppID,
			userAgentReg: userAgent,
			userAgentDel: userAgent,
			ipReg:        ip,
			ipDel:        ip,
			expectedErr:  le.ErrAppIDIsRequired,
		},
		{
			name:         "Delete user with empty userAgent",
			appID:        appID,
			userAgentReg: userAgent,
			userAgentDel: "",
			ipReg:        ip,
			ipDel:        ip,
			expectedErr:  le.ErrUserAgentIsRequired,
		},
		{
			name:         "Delete user with empty ip",
			appID:        appID,
			userAgentReg: userAgent,
			userAgentDel: userAgent,
			ipReg:        ip,
			ipDel:        "",
			expectedErr:  le.ErrIPIsRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Register user
			resp, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    gofakeit.Email(),
				Password: randomFakePassword(),
				AppId:    appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgentReg,
					Ip:        tt.ipReg,
				},
			})
			require.NoError(t, err)
			require.NotEmpty(t, resp.GetTokenData())

			// Get token and place it in metadata
			token := resp.GetTokenData()
			require.NotEmpty(t, token)
			require.NotEmpty(t, token.AccessToken)

			md := metadata.Pairs(token.AccessTokenKey, token.AccessToken)

			// Create context for Logout request
			ctx = metadata.NewOutgoingContext(ctx, md)
			// Delete user
			_, err = st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{
				AppId: tt.appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: tt.userAgentDel,
					Ip:        tt.ipDel,
				},
			})
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}
