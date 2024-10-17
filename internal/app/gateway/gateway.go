package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	gw "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/config/settings"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

type App struct {
	log        *slog.Logger
	HTTPServer *http.Server
}

func New(
	ctx context.Context,
	log *slog.Logger,
	grpcConfig settings.GRPCServer,
	gatewayConfig settings.HTTPServer,
) *App {
	const method = "gateway.New"

	mux := runtime.NewServeMux()

	addr := fmt.Sprintf("%s:%s", grpcConfig.Host, grpcConfig.Port)

	retryOpts := []retry.CallOption{
		retry.WithCodes(codes.NotFound, codes.Aborted, codes.DeadlineExceeded),
		retry.WithMax(uint(grpcConfig.RetriesCount)),
		retry.WithPerRetryTimeout(grpcConfig.Timeout),
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(retry.UnaryClientInterceptor(retryOpts...)),
	}

	err := gw.RegisterAuthHandlerFromEndpoint(ctx, mux, addr, opts)
	if err != nil {
		log.Error(fmt.Sprintf("%s: failed to register auth handler from endpoint: %v", method, err))
		return nil
	}

	httpServer := &http.Server{
		Addr:         gatewayConfig.Address,
		Handler:      mux,
		ReadTimeout:  gatewayConfig.Timeout,
		WriteTimeout: gatewayConfig.Timeout,
		IdleTimeout:  gatewayConfig.IdleTimeout,
	}

	return &App{
		log:        log,
		HTTPServer: httpServer,
	}
}

func (a *App) Start() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shutdownComplete := handleShutdown(func() {
		if err := a.HTTPServer.Shutdown(ctx); err != nil {
			a.log.Error("httpserver.Shutdown failed")
		}
	})

	if err := a.HTTPServer.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
		<-shutdownComplete
	} else {
		a.log.Error("httpserver.ListenAndServe failed")
	}

	a.log.Info("httpserver stopped")
}

func handleShutdown(onShutdownSignal func()) <-chan struct{} {
	shutdown := make(chan struct{})

	go func() {
		shutdownSignal := make(chan os.Signal, 1)
		signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)

		<-shutdownSignal

		onShutdownSignal()
		close(shutdown)
	}()

	return shutdown
}
