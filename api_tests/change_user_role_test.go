package api_tests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	grpcController "github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain"
	"github.com/rshelekhov/sso/internal/domain/service/rbac"
	"github.com/rshelekhov/sso/internal/lib/interceptor/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestChangeUserRole_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Register and login admin
	admin, cleanupAdmin := registerAndLoginAdmin(t, st, ctx)
	defer cleanupAdmin()

	// Register regular user
	regularEmail := gofakeit.Email()
	regularPass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           regularEmail,
		Password:        regularPass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	regularToken := respReg.GetTokenData()
	regularAccessToken := regularToken.GetAccessToken()

	// Get regular user's ID
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, regularAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respUser, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)
	regularUserID := respUser.GetUser().GetId()

	// Change regular user's role to admin
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respChangeRole, err := st.AuthClient.ChangeUserRole(ctx, &ssov1.ChangeUserRoleRequest{
		UserId: regularUserID,
		Role:   rbac.RoleAdmin.String(),
	})
	require.NoError(t, err)
	require.True(t, respChangeRole.GetSuccess())

	// Get regular user's role using admin token
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respRole, err := st.AuthClient.GetUserRole(ctx, &ssov1.GetUserRoleRequest{
		UserId: regularUserID,
	})
	require.NoError(t, err)
	require.Equal(t, rbac.RoleAdmin.String(), respRole.GetRole())

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: regularToken,
	}
	cleanup(params, cfg.AppID)
}

func TestChangeUserRole_UserNotFound(t *testing.T) {
	ctx, st := suite.New(t)

	// Register and login admin
	admin, cleanupAdmin := registerAndLoginAdmin(t, st, ctx)
	defer cleanupAdmin()

	// Change regular user's role to admin
	md := metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respChangeRole, err := st.AuthClient.ChangeUserRole(ctx, &ssov1.ChangeUserRoleRequest{
		UserId: "non-existent-user-id",
		Role:   rbac.RoleAdmin.String(),
	})
	require.Nil(t, respChangeRole)
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrUserNotFound.Error())
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestChangeUserRole_ValidationErrors(t *testing.T) {
	ctx, st := suite.New(t)

	// Register and login admin
	admin, cleanupAdmin := registerAndLoginAdmin(t, st, ctx)
	defer cleanupAdmin()

	// Register regular user
	regularEmail := gofakeit.Email()
	regularPass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           regularEmail,
		Password:        regularPass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	regularToken := respReg.GetTokenData()
	regularAccessToken := regularToken.GetAccessToken()

	// Get regular user's ID
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, regularAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respUser, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)
	regularUserID := respUser.GetUser().GetId()

	tests := []struct {
		name        string
		userID      string
		role        string
		errContains string
	}{
		{
			name:        "empty userID",
			userID:      "",
			role:        rbac.RoleAdmin.String(),
			errContains: grpcController.ErrUserIDIsRequired.Error(),
		},
		{
			name:        "empty role",
			userID:      regularUserID,
			role:        "",
			errContains: grpcController.ErrRoleIsRequired.Error(),
		},
		{
			name:        "invalid role",
			userID:      regularUserID,
			role:        "invalid-role",
			errContains: grpcController.ErrInvalidRoleProvided.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Change regular user's role using admin token
			md = metadata.Pairs(appid.Header, cfg.AppID)
			md.Append(jwtauth.AuthorizationHeader, admin.accessToken)
			ctx = metadata.NewOutgoingContext(ctx, md)

			respChangeRole, err := st.AuthClient.ChangeUserRole(ctx, &ssov1.ChangeUserRoleRequest{
				UserId: tt.userID,
				Role:   tt.role,
			})
			require.Nil(t, respChangeRole)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errContains)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: regularToken,
	}
	cleanup(params, cfg.AppID)
}

func TestChangeUserRole_PermissionDenied(t *testing.T) {
	ctx, st := suite.New(t)

	// Register and login admin
	_, cleanupAdmin := registerAndLoginAdmin(t, st, ctx)
	defer cleanupAdmin()

	// Register regular user
	regularEmail := gofakeit.Email()
	regularPass := randomFakePassword()
	userAgent := gofakeit.UserAgent()
	ip := gofakeit.IPv4Address()

	md := metadata.Pairs(appid.Header, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respReg, err := st.AuthClient.RegisterUser(ctx, &ssov1.RegisterUserRequest{
		Email:           regularEmail,
		Password:        regularPass,
		VerificationUrl: cfg.VerificationURL,
		UserDeviceData: &ssov1.UserDeviceData{
			UserAgent: userAgent,
			Ip:        ip,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, respReg.GetTokenData())

	regularToken := respReg.GetTokenData()
	regularAccessToken := regularToken.GetAccessToken()

	// Get regular user's ID
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, regularAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	respUser, err := st.AuthClient.GetUser(ctx, &ssov1.GetUserRequest{})
	require.NoError(t, err)
	regularUserID := respUser.GetUser().GetId()

	// Try to change regular user's role to admin
	md = metadata.Pairs(appid.Header, cfg.AppID)
	md.Append(jwtauth.AuthorizationHeader, regularAccessToken)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// We expect error because user is not admin
	respChangeRole, err := st.AuthClient.ChangeUserRole(ctx, &ssov1.ChangeUserRoleRequest{
		UserId: regularUserID,
		Role:   rbac.RoleAdmin.String(),
	})
	require.Nil(t, respChangeRole)
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	// Cleanup database after test
	params := cleanupParams{
		t:     t,
		st:    st,
		appID: cfg.AppID,
		token: regularToken,
	}
	cleanup(params, cfg.AppID)
}
