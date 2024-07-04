package api_tests

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetJWKSHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	resp, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
		AppId: appID,
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

func TestGetJWKSFailCases(t *testing.T) {
	ctx, st := suite.New(t)

	tests := []struct {
		name        string
		appID       string
		expectedErr error
	}{
		{
			name:        "GetJWKS with empty appID",
			appID:       emptyAppID,
			expectedErr: le.ErrAppIDIsRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := st.AuthClient.GetJWKS(ctx, &ssov1.GetJWKSRequest{
				AppId: tt.appID,
			})
			require.Contains(t, err.Error(), tt.expectedErr.Error())
		})
	}
}
