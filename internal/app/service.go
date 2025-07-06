package app

import (
	"log/slog"

	"github.com/redis/go-redis/v9"
	"github.com/rshelekhov/sso/internal/config"
	ssogrpc "github.com/rshelekhov/sso/internal/controller/grpc"
	"github.com/rshelekhov/sso/internal/domain/service/clientvalidator"
	authenticate "github.com/rshelekhov/sso/internal/lib/interceptor/auth"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/internal/lib/interceptor/requestid"
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

	return []grpc.UnaryServerInterceptor{
		requestIDInterceptor.UnaryServerInterceptor(),
		clientIDInterceptor.UnaryServerInterceptor(),
		authenticate.UnaryServerInterceptor(s.methodsConfig, s.jwtMiddleware.UnaryServerInterceptor()),
	}
}
