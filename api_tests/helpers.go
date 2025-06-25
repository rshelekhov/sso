//nolint:staticcheck
package api_tests

import (
	"context"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const (
	emptyValue        = ""
	clientID          = "test-app-id"
	passDefaultLength = 10
)

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLength)
}

type cleanupParams struct {
	t        *testing.T
	st       *suite.Suite
	clientID string
	token    *authv1.TokenData
}

func cleanup(params cleanupParams, clientID string) {
	// Create context with access token and clientID for Delete user request
	md := metadata.Pairs(jwtauth.AuthorizationHeader, params.token.GetAccessToken())
	md.Append(clientid.Header, clientID)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Delete user
	_, err := params.st.UserService.DeleteUser(ctx, &userv1.DeleteUserRequest{})
	require.NoError(params.t, err)
}
