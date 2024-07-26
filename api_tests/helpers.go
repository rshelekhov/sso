package api_tests

import (
	"context"
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/jwt/jwtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
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

func cleanup(params cleanupParams) {
	// Create context with access token for Delete user request
	md := metadata.Pairs(jwtoken.AccessTokenKey, params.token.AccessToken)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Delete user
	_, err := params.st.AuthClient.DeleteUser(ctx, &ssov1.DeleteUserRequest{
		AppId: params.appID,
	})
	require.NoError(params.t, err)
}
