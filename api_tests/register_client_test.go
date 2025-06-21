package api_tests

import (
	"testing"

	"github.com/rshelekhov/sso/internal/domain"

	"github.com/brianvoe/gofakeit/v6"
	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/stretchr/testify/require"
)

func TestRegisterClient_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	clientName := gofakeit.Word()

	// Register app
	_, err := st.ClientManagementService.RegisterClient(ctx, &clientv1.RegisterClientRequest{
		ClientName: clientName,
	})
	require.NoError(t, err)
}

func TestRegisterClient_ClientAlreadyExists(t *testing.T) {
	ctx, st := suite.New(t)

	clientName := gofakeit.Word()

	// Register app
	_, err := st.ClientManagementService.RegisterClient(ctx, &clientv1.RegisterClientRequest{
		ClientName: clientName,
	})
	require.NoError(t, err)

	// Register app again
	_, err = st.ClientManagementService.RegisterClient(ctx, &clientv1.RegisterClientRequest{
		ClientName: clientName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrClientAlreadyExists.Error())
}
