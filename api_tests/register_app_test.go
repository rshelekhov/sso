package api_tests

import (
	"errors"
	"github.com/brianvoe/gofakeit/v6"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/api_tests/mocks"
	"github.com/rshelekhov/sso/api_tests/suite"
	"github.com/rshelekhov/sso/internal/config"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
	"github.com/rshelekhov/sso/internal/usecase"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"log/slog"
	"os"
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

// TestRegisterApp_GeneratePrivateKeyError tests the scenario where the GeneratePrivateKey function
// returns an error and then app is deleted
func TestRegisterApp_GeneratePrivateKeyError(t *testing.T) {
	ctx, _ := suite.New(t)

	// Create mocks
	mockTS := mocks.NewMockTokenService()
	mockStorage := new(mocks.MockAppStorage)

	// Set up the mock to return an error when GeneratePrivateKey is called
	mockTS.On("GeneratePrivateKey", mock.Anything).Return(errors.New("failed to generate PEM key pair"))
	mockStorage.On("RegisterApp", mock.Anything, mock.Anything).Return(nil)
	mockStorage.On("DeleteApp", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	cfg := &config.ServerSettings{
		DefaultHashBcrypt: config.HashBcryptConfig{
			Salt: "salt",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create an instance of AppUsecase with the mocks
	appUsecase := usecase.NewAppUsecase(cfg, log, mockStorage, mockTS)

	appName := gofakeit.Word()

	// Register app and expect an error
	err := appUsecase.RegisterApp(ctx, appName)
	require.Error(t, err)
	require.Contains(t, err.Error(), "internal server error")

	// Verify that GeneratePrivateKey was called
	mockTS.AssertCalled(t, "GeneratePrivateKey", mock.Anything)

	// Verify that DeleteApp was called after the error
	mockStorage.AssertCalled(t, "DeleteApp", mock.Anything, mock.Anything, mock.Anything)

	// Assert that no other methods on mockTS were called
	mockTS.AssertExpectations(t)
}

// TestRegisterApp_GeneratePrivateKeyError_DeleteAppError tests the scenario where the GeneratePrivateKey function
// returns an error, and then we get an error when deleting the app
func TestRegisterApp_GeneratePrivateKeyError_DeleteAppError(t *testing.T) {
	ctx, _ := suite.New(t)

	// Create mocks
	mockTS := mocks.NewMockTokenService()
	mockStorage := new(mocks.MockAppStorage)

	// Set up the mock to return an error when GeneratePrivateKey is called
	mockTS.On("GeneratePrivateKey", mock.Anything).Return(errors.New("failed to generate PEM key pair"))
	mockStorage.On("RegisterApp", mock.Anything, mock.Anything).Return(nil)
	mockStorage.On("DeleteApp", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to delete app"))

	cfg := &config.ServerSettings{
		DefaultHashBcrypt: config.HashBcryptConfig{
			Salt: "salt",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create an instance of AppUsecase with the mocks
	appUsecase := usecase.NewAppUsecase(cfg, log, mockStorage, mockTS)

	appName := gofakeit.Word()

	// Register app and expect an error
	err := appUsecase.RegisterApp(ctx, appName)
	require.Error(t, err)
	require.Contains(t, err.Error(), "internal server error")

	// Verify that GeneratePrivateKey was called
	mockTS.AssertCalled(t, "GeneratePrivateKey", mock.Anything)

	// Verify that DeleteApp was called after the error
	mockStorage.AssertCalled(t, "DeleteApp", mock.Anything, mock.Anything, mock.Anything)

	// Assert that no other methods on mockTS were called
	mockTS.AssertExpectations(t)
}
