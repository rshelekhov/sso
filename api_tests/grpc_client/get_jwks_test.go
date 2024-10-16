package grpc_client

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/grpc_client/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetJWKS_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	resp, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
		AppID: cfg.AppID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetJwks())
	require.NotEmpty(t, resp.GetJwks()[0])
	require.NotEmpty(t, resp.GetJwks()[0].GetAlg())
	require.NotEmpty(t, resp.GetJwks()[0].GetKty())
	require.NotEmpty(t, resp.GetJwks()[0].GetUse())
	require.NotEmpty(t, resp.GetJwks()[0].GetKid())
	require.NotEmpty(t, resp.GetJwks()[0].GetN())
	require.NotEmpty(t, resp.GetJwks()[0].GetE())
	require.NotEmpty(t, resp.GetTtl())
}

func TestGetJWKS_FailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		appID       string
		expectedErr error
	}{
		{
			name:        "GetJWKS with empty appID",
			appID:       emptyValue,
			expectedErr: le.ErrAppIDIsRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
				AppID: tt.appID,
			})
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}
