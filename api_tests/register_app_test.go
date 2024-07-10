package api_tests

import (
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/stretchr/testify/require"
	"testing"
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

func TestRegisterApp_EmptyAppName(t *testing.T) {
	ctx, st := suite.New(t)

	// Register app
	_, err := st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: "",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), le.ErrAppNameIsRequired.Error())
}

func TestRegisterApp_AppNameWithSpaces(t *testing.T) {
	ctx, st := suite.New(t)

	appName := gofakeit.Word() + " " + gofakeit.Word()

	// Register app
	_, err := st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: appName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), le.ErrAppNameCannotContainSpaces.Error())
}

func TestRegisterApp_AppAlreadyExists(t *testing.T) {
	ctx, st := suite.New(t)

	appName := gofakeit.Word()

	// Register first app
	_, err := st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: appName,
	})
	require.NoError(t, err)

	// Register second app
	_, err = st.AuthClient.RegisterApp(ctx, &ssov1.RegisterAppRequest{
		AppName: appName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), le.ErrAppAlreadyExists.Error())
}
