package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/redis/go-redis/v9"
	"github.com/rshelekhov/golib/middleware/requestid"
	"github.com/rshelekhov/sso/internal/config"
	ssogrpc "github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	authenticate "github.com/rshelekhov/sso/internal/lib/interceptor/auth"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	metricsInterceptor "github.com/rshelekhov/sso/internal/lib/interceptor/metrics"
	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	authv1 "github.com/rshelekhov/sso-protos/gen/go/api/auth/v1"
	clientv1 "github.com/rshelekhov/sso-protos/gen/go/api/client/v1"
	userv1 "github.com/rshelekhov/sso-protos/gen/go/api/user/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SSOService struct {
	log             *slog.Logger
	jwtMiddleware   jwtauth.Middleware
	clientValidator clientvalidator.Validator
	clientUsecase   ssogrpc.ClientUsecase
	authUsecase     ssogrpc.AuthUsecase
	userUsecase     ssogrpc.UserUsecase
	redisClient     *redis.Client
	methodsConfig   *config.GRPCMethodsConfig
	metrics         *infrastructure.GRPCServerMetrics
}

func NewSSOService(
	log *slog.Logger,
	jwtMiddleware jwtauth.Middleware,
	clientValidator clientvalidator.Validator,
	clientUsecase ssogrpc.ClientUsecase,
	authUsecase ssogrpc.AuthUsecase,
	userUsecase ssogrpc.UserUsecase,
	redisClient *redis.Client,
	methodsConfig *config.GRPCMethodsConfig,
	metrics *infrastructure.GRPCServerMetrics,
) *SSOService {
	return &SSOService{
		log:             log,
		jwtMiddleware:   jwtMiddleware,
		clientValidator: clientValidator,
		clientUsecase:   clientUsecase,
		authUsecase:     authUsecase,
		userUsecase:     userUsecase,
		redisClient:     redisClient,
		methodsConfig:   methodsConfig,
		metrics:         metrics,
	}
}

func (s *SSOService) RegisterGRPC(grpcServer *grpc.Server) {
	ssogrpc.RegisterController(
		grpcServer,
		s.log,
		s.clientValidator,
		s.clientUsecase,
		s.authUsecase,
		s.userUsecase,
	)
}

func (s *SSOService) RegisterHTTP(ctx context.Context, mux *runtime.ServeMux) error {
	// Connect to the gRPC server running on localhost
	// The HTTP gateway acts as a client to the gRPC server
	grpcAddr := "localhost:44044"
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	// Register Auth service HTTP handlers
	if err := authv1.RegisterAuthServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return fmt.Errorf("failed to register auth service HTTP handler: %w", err)
	}

	// Register User service HTTP handlers
	if err := userv1.RegisterUserServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return fmt.Errorf("failed to register user service HTTP handler: %w", err)
	}

	// Register Client service HTTP handlers
	if err := clientv1.RegisterClientManagementServiceHandlerFromEndpoint(ctx, mux, grpcAddr, opts); err != nil {
		return fmt.Errorf("failed to register client service HTTP handler: %w", err)
	}

	return nil
}

func (s *SSOService) GetCustomInterceptors() []grpc.UnaryServerInterceptor {
	requestIDInterceptor := requestid.NewInterceptor()
	clientIDInterceptor := clientid.NewInterceptor(s.methodsConfig)

	interceptors := []grpc.UnaryServerInterceptor{
		requestIDInterceptor.UnaryServerInterceptor(),
		clientIDInterceptor.UnaryServerInterceptor(),
		authenticate.UnaryServerInterceptor(s.methodsConfig, s.jwtMiddleware.UnaryServerInterceptor()),
	}

	// Only add metrics interceptor if metrics are enabled
	if s.metrics != nil {
		metricsInterceptor := metricsInterceptor.NewInterceptor(s.metrics)
		interceptors = append(interceptors, metricsInterceptor.UnaryServerInterceptor())
	}

	return interceptors
}
