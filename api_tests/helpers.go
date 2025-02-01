package api_tests

import (
	"context"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/rshelekhov/jwtauth"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

const (
	emptyValue        = ""
	appID             = "test-app-id"
	passDefaultLength = 10
)

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, true, passDefaultLength)
}

type cleanupParams struct {
	t     *testing.T
	st    *suite.Suite
	appID string
	token *ssov1.TokenData
}

func cleanup(params cleanupParams, appID string) {
	// Create context with access token and appID for Delete user request
	md := metadata.Pairs(jwtauth.AuthorizationHeader, params.token.GetAccessToken())
	md.Append(appid.Header, appID)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Delete user
	_, err := params.st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{})
	require.NoError(params.t, err)
}
