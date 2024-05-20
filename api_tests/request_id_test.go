package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestRequestIDHappyPath(t *testing.T) {
	tests := []struct {
		name            string
		firstRequestID  string
		secondRequestID string
	}{
		{
			name:            "Without requestID from the client side",
			firstRequestID:  "",
			secondRequestID: "",
		},
		{
			name:           "With requestID from the client side",
			firstRequestID: "requestID #1 from the client side",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, st := suite.New(t)

			// Create metadata
			md := metadata.Pairs()
			if tc.firstRequestID != "" {
				md.Append(key.RequestID, tc.firstRequestID)
			}

			// Create context with metadata
			ctx = metadata.NewOutgoingContext(ctx, md)

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

			// Get jwtoken and place it in metadata
			token := respReg.GetTokenData()
			require.NotEmpty(t, token)
			require.NotEmpty(t, token.AccessToken)

			md = metadata.Pairs(jwtoken.AccessTokenKey, token.AccessToken)

			if tc.secondRequestID != "" {
				md.Append(key.RequestID, tc.secondRequestID)
			}

			// Create context for Logout request
			ctx = metadata.NewOutgoingContext(ctx, md)

			// Logout user
			_, err = st.AuthClient.Logout(ctx, &ssov1.LogoutRequest{
				AppId: appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: userAgent,
					Ip:        ip,
				},
			})
			require.NoError(t, err)
		})
	}
}
