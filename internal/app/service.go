package app

import (
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/rshelekhov/sso/internal/config"
	ssogrpc "github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	authenticate "github.com/rshelekhov/sso/internal/lib/interceptor/auth"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	metricsInterceptor "github.com/rshelekhov/sso/internal/lib/interceptor/metrics"
	"github.com/rshelekhov/sso/internal/lib/interceptor/requestid"
	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
	"github.com/rshelekhov/sso/pkg/jwtauth"
	"google.golang.org/grpc"
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
