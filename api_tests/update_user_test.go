package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestUpdateUser_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add appID to gRPC metadata
	md := metadata.Pairs()
	md.Append(appid.HeaderKey, cfg.AppID)
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

	// Get access token and place it in metadata
	accessToken := token.GetAccessToken()
	require.NotEmpty(t, accessToken)

	md = metadata.Pairs(jwtauth.AccessTokenKey, accessToken)

	// Create context for Update user request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Update user
	_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
		Email:           gofakeit.Email(),
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
	})
	require.NoError(t, err)

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: token,
	}
	cleanup(params, cfg.AppID)
}

func TestUpdateUser_EmailAlreadyTaken(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	emailTaken := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add appID to gRPC metadata
	md := metadata.Pairs()
	md.Append(appid.HeaderKey, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user for taking email
	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           emailTaken,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
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
		VerificationUrl: cfg.VerificationURL,
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

	md = metadata.Pairs(jwtauth.AccessTokenKey, accessToken)

	// Create context for Update user request
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Update user
	_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
		Email:           emailTaken,
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrEmailAlreadyTaken.Error())

	// Cleanup database after test
	tokens := []*ssov1.TokenData{token1, token2}
	for _, token := range tokens {
		params := cleanupParams{
			t:     t,
			st:    st,
			appID: cfg.AppID,
			token: token,
		}
		cleanup(params, cfg.AppID)
	}
}

func TestUpdateUser_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add appID to gRPC metadata
	md := metadata.Pairs()
	md.Append(appid.HeaderKey, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

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
			name:        "Current password is incorrect",
			regEmail:    gofakeit.Email(),
			curPassword: randomFakePassword(),
			updPassword: randomFakePassword(),
			appID:       cfg.AppID,
			expectedErr: domain.ErrPasswordsDoNotMatch,
		},
		{
			name:        "Current password is empty",
			regEmail:    gofakeit.Email(),
			curPassword: "",
			updPassword: pass,
			appID:       cfg.AppID,
			expectedErr: domain.ErrCurrentPasswordRequired,
		},
		{
			name:        "No password changes detected",
			regEmail:    gofakeit.Email(),
			curPassword: pass,
			updPassword: pass,
			appID:       cfg.AppID,
			expectedErr: domain.ErrNoPasswordChangesDetected,
		},
		{
			name:        "No email changes detected",
			appID:       cfg.AppID,
			expectedErr: domain.ErrNoEmailChangesDetected,
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
				VerificationUrl: cfg.VerificationURL,
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

			md := metadata.Pairs(jwtauth.AccessTokenKey, accessToken)

			// Create context for Logout request
			ctx = metadata.NewOutgoingContext(ctx, md)

			// Update user
			_, err = st.AuthClient.UpdateUser(ctx, &ssov1.UpdateUserRequest{
				Email:           tt.updEmail,
				CurrentPassword: tt.curPassword,
				UpdatedPassword: tt.updPassword,
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
			cleanup(params, cfg.AppID)
		})
	}
}
