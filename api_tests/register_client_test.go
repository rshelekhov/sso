package api_tests

import (
	"testing"

	"github.com/rshelekhov/sso/internal/domain"

	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/stretchr/testify/require"
)

func TestRegisterApp_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	appName := gofakeit.Word()

	// Register app
	_, err := st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: appName,
	})
	require.NoError(t, err)
}

func TestRegisterApp_AppAlreadyExists(t *testing.T) {
	ctx, st := suite.New(t)

	appName := gofakeit.Word()

	// Register app
	_, err := st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: appName,
	})
	require.NoError(t, err)

	// Register app again
	_, err = st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: appName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), domain.ErrClientAlreadyExists.Error())
}
