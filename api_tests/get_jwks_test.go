package api_tests

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/pkg/middleware/appid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"testing"
)

func TestGetJWKS_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	// Add appID to gRPC metadata
	md := metadata.Pairs()
	md.Append(appid.HeaderKey, cfg.AppID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{})
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
