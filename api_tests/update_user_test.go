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

func TestUpdateUserHappyPath(t *testing.T) {
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

	// Get jwtoken and place it in metadata
	token := respReg.GetTokenData()
	require.NotEmpty(t, token)
	require.NotEmpty(t, token.AccessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, token.AccessToken)

	// Create context for Logout request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Update user
	_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
		Email:           gofakeit.Email(),
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
		AppId:           appID,
	})
	require.NoError(t, err)
}

func TestUpdateUserFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for register request
	email := gofakeit.Email()
	emailTaken := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	tests := []struct {
		name        string
		regEmail    string
		updEmail    string
		curPassword string
		updPassword string
		appID       int32
		expectedErr error
	}{
		{
			name:        "Update user with empty appID",
			regEmail:    gofakeit.Email(),
			updEmail:    gofakeit.Email(),
			curPassword: pass,
			updPassword: randomFakePassword(),
			appID:       emptyAppID,
			expectedErr: le.ErrAppIDIsRequired,
		},
		{
			name:        "Email already taken",
			regEmail:    gofakeit.Email(),
			updEmail:    emailTaken,
			appID:       appID,
			expectedErr: le.ErrEmailAlreadyTaken,
		},
		{
			name:        "Current password is incorrect",
			regEmail:    email,
			curPassword: randomFakePassword(),
			updPassword: randomFakePassword(),
			appID:       appID,
			expectedErr: le.ErrCurrentPasswordIsIncorrect,
		},
		{
			name:        "No password changes detected",
			regEmail:    gofakeit.Email(),
			curPassword: pass,
			updPassword: pass,
			appID:       appID,
			expectedErr: le.ErrNoPasswordChangesDetected,
		},
		{
			name:        "No email changes detected",
			appID:       appID,
			expectedErr: le.ErrNoEmailChangesDetected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "No email changes detected" {
				email = gofakeit.Email()
				tt.regEmail = email
				tt.updEmail = email
			}

			// Register user
			respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
				Email:    tt.regEmail,
				Password: pass,
				AppId:    appID,
				UserDeviceData: &ssov1.UserDeviceData{
					UserAgent: userAgent,
					Ip:        ip,
				},
			})
			require.NoError(t, err)
			require.NotEmpty(t, respReg.GetTokenData())

			if tt.name == "Email already taken" {
				_, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
					Email:    emailTaken,
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

			// Get jwtoken and place it in metadata
			token := respReg.GetTokenData()
			require.NotEmpty(t, token)
			require.NotEmpty(t, token.AccessToken)

			md := metadata.Pairs(jwtoken.AccessTokenKey, token.AccessToken)

			// Create context for Logout request
			ctx = metadata.NewOutgoingContext(ctx, md)

			// Update user
			_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
				Email:           tt.updEmail,
				CurrentPassword: tt.curPassword,
				UpdatedPassword: tt.updPassword,
				AppId:           tt.appID,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}
