package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestUpdateUser_HappyPath(t *testing.T) {
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

	// Get access token and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, accessToken)

	// Create context for Update user request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Update user
	_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
		Email:           gofakeit.Email(),
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
		AppId:           cfg.AppID,
	})
	require.NoError(t, err)

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params)
}

func TestUpdateUser_EmailAlreadyTaken(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	emailTaken := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Register user for taking email
	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           emailTaken,
		Password:        pass,
		AppId:           cfg.AppID,
		VerificationURL: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	token1 := respReg.GetTokenData()
	require.NotEmpty(t, token1)

	// Register user
	resp2Reg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
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

	token2 := resp2Reg.GetTokenData()
	require.NotEmpty(t, token2)

	// Get access and place it in metadata
	accessToken := token2.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md := metadata.Pairs(jwtoken.AccessTokenKey, accessToken)

	// Create context for Update user request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Update user
	_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
		Email:           emailTaken,
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
		AppId:           cfg.AppID,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), le.ErrEmailAlreadyTaken.Error())

	// Cleanup database after test
	tokens := []*ssov1.TokenData{token1, token2}
	for _, token := range tokens {
		params := cleanupParams{
			t:     t,
			st:    st,
			appID: cfg.AppID,
			token: token,
		}
		cleanup(params)
	}
}

func TestUpdateUser_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	tests := []struct {
		name        string
		regEmail    string
		updEmail    string
		curPassword string
		updPassword string
		appID       string
		expectedErr error
	}{
		{
			name:        "Update user with empty appID",
			regEmail:    gofakeit.Email(),
			updEmail:    gofakeit.Email(),
			curPassword: pass,
			updPassword: randomFakePassword(),
			appID:       emptyValue,
			expectedErr: le.ErrAppIDIsRequired,
		},
		{
			name:        "Current password is incorrect",
			regEmail:    gofakeit.Email(),
			curPassword: randomFakePassword(),
			updPassword: randomFakePassword(),
			appID:       cfg.AppID,
			expectedErr: le.ErrCurrentPasswordIsIncorrect,
		},
		{
			name:        "No password changes detected",
			regEmail:    gofakeit.Email(),
			curPassword: pass,
			updPassword: pass,
			appID:       cfg.AppID,
			expectedErr: le.ErrNoPasswordChangesDetected,
		},
		{
			name:        "No email changes detected",
			appID:       cfg.AppID,
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
			respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
				Email:           tt.regEmail,
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

			// Get access and place it in metadata
			accessToken := token.GetAccessToken()
			require.NotEmpty(t, accessToken)

			md := metadata.Pairs(jwtoken.AccessTokenKey, accessToken)

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

			// Cleanup database after test
			params := cleanupParams{
				t:     t,
				st:    st,
				appID: cfg.AppID,
				token: token,
			}
			cleanup(params)
		})
	}
}
