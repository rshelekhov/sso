package suite

import (
	"context"
	"github.com/rshelekhov/sso/api_tests/grpc_client/suite/storage/postgres"
	"net"
	"os"
	"testing"

	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T
	Cfg        *config.ServerSettings
	AuthClient ssov1.AuthClient
	Storage    *postgres.TestStorage
}

const (
	//nolint:revive
	CONFIG_PATH       = "CONFIG_PATH"
	defaultConfigPath = "../config/.env"
	grpcHost          = "localhost"
)

// New creates new test suite
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadPath(configPath())

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPCServer.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	cc, err := grpc.NewClient(grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal("grpc server connection failed: ", err)
	}

	storage, err := postgres.NewTestStorage(cfg)
	if err != nil {
		t.Fatal(err)
	}

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: ssov1.NewAuthClient(cc),
		Storage:    storage,
	}
}

func configPath() string {
	if v := os.Getenv(CONFIG_PATH); v != "" {
		return v
	}

	return defaultConfigPath
}

func grpcAddress(cfg *config.ServerSettings) string {
	return net.JoinHostPort(grpcHost, cfg.GRPCServer.Port)
}
