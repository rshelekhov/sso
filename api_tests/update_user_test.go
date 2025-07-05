package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/pkg/jwtauth"
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

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user
	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
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

	// Create context for Update user request
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	updatedEmail := gofakeit.Email()

	// Update user
	resp, err := st.UserService.UpdateUser(ctx, &userv1.UpdateUserRequest{
		Email:           updatedEmail,
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp)
	require.Equal(t, updatedEmail, resp.GetEmail())

	// Cleanup database after test
	params := cleanupParams{
		t:        t,
		st:       st,
		clientID: cfg.ClientID,
		token:    token,
	}
	cleanup(params, cfg.ClientID)
}

func TestUpdateUser_EmailAlreadyTaken(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	emailTaken := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Register user for taking email
	respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           emailTaken,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)

	token1 := respReg.GetTokenData()
	require.NotEmpty(t, token1)

	// Register user
	resp2Reg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
		Email:           email,
		Password:        pass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &authv1.UserDeviceData{
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

	// Create context for Update user request
	md = metadata.Pairs(clientid.Header, cfg.ClientID)
	md.Append(jwtauth.AuthorizationHeader, accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Update user
	_, err = st.UserService.UpdateUser(ctx, &userv1.UpdateUserRequest{
		Email:           emailTaken,
		CurrentPassword: pass,
		UpdatedPassword: randomFakePassword(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrEmailAlreadyTaken.Error())

	// Cleanup database after test
	tokens := []*authv1.TokenData{token1, token2}
	for _, token := range tokens {
		params := cleanupParams{
			t:        t,
			st:       st,
			clientID: cfg.ClientID,
			token:    token,
		}
		cleanup(params, cfg.ClientID)
	}
}

func TestUpdateUser_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	// Generate data for requests
	email := gofakeit.Email()
	pass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	tests := []struct {
		name        string
		regEmail    string
		updEmail    string
		curPassword string
		updPassword string
		clientID    string
		expectedErr error
	}{
		{
			name:        "Current password is incorrect",
			regEmail:    gofakeit.Email(),
			curPassword: randomFakePassword(),
			updPassword: randomFakePassword(),
			clientID:    cfg.ClientID,
			expectedErr: domain.ErrPasswordsDoNotMatch,
		},
		{
			name:        "Current password is empty",
			regEmail:    gofakeit.Email(),
			curPassword: "",
			updPassword: pass,
			clientID:    cfg.ClientID,
			expectedErr: domain.ErrCurrentPasswordRequired,
		},
		{
			name:        "No password changes detected",
			regEmail:    gofakeit.Email(),
			curPassword: pass,
			updPassword: pass,
			clientID:    cfg.ClientID,
			expectedErr: domain.ErrNoPasswordChangesDetected,
		},
		{
			name:        "No email changes detected",
			clientID:    cfg.ClientID,
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
			respReg, err := st.AuthService.RegisterUser(ctx, &authv1.RegisterUserRequest{
				Email:           tt.regEmail,
				Password:        pass,
				VerificationUrl: cfg.VerificationURL,
				UserDeviceData: &authv1.UserDeviceData{
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

			// Create context for Logout request
			md = metadata.Pairs(clientid.Header, cfg.ClientID)
			md.Append(jwtauth.AuthorizationHeader, accessToken)
			ctx = metadata.NewOutgoingContext(ctx, md)

			// Update user
			_, err = st.UserService.UpdateUser(ctx, &userv1.UpdateUserRequest{
				Email:           tt.updEmail,
				CurrentPassword: tt.curPassword,
				UpdatedPassword: tt.updPassword,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr.Error())

			// Cleanup database after test
			params := cleanupParams{
				t:        t,
				st:       st,
				clientID: cfg.ClientID,
				token:    token,
			}
			cleanup(params, cfg.ClientID)
		})
	}
}
