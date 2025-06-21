package api_tests

import (
	"testing"

	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestGetJWKS_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Add clientID to gRPC metadata
	md := metadata.Pairs(clientid.Header, cfg.ClientID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := st.AuthService.GetJWKS(ctx, &authv1.GetJWKSRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetJwks())
	require.NotEmpty(t, resp.GetJwks()[0])
	require.NotEmpty(t, resp.GetJwks()[0].GetAlg())
	require.NotEmpty(t, resp.GetJwks()[0].GetKty())
	require.NotEmpty(t, resp.GetJwks()[0].GetUse())
	require.NotEmpty(t, resp.GetJwks()[0].GetKid())
	require.NotEmpty(t, resp.GetJwks()[0].GetN())
	require.NotEmpty(t, resp.GetJwks()[0].GetE())
}
