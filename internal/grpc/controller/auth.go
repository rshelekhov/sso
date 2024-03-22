package auth

import (
	"context"
	"errors"
	"fmt"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constants/key"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/model"
	"github.com/rshelekhov/sso/internal/port"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"log/slog"
)

type authController struct {
	ssov1.UnimplementedAuthServer
	log     logger.Interface
	usecase port.AuthUsecase
}

func RegisterController(gRPC *grpc.Server, log logger.Interface, usecase port.AuthUsecase) {
	ssov1.RegisterAuthServer(gRPC, &authController{log: log, usecase: usecase})
}

func (c *authController) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	const op = "authController.Login"

	// Get request ID
	reqID, err := extractRequestID(ctx, c.log, op)
	if err != nil {
		return nil, err
	}

	log := logger.LogWithRequest(c.log, op, reqID)

	// Get user device data
	userDevice, err := extractUserDeviceData(ctx, log)
	if err != nil {
		return nil, err
	}

	// Validate request
	userInput := &model.UserRequestData{}
	if err = validateLogin(req, userInput); err != nil {
		return nil, err
	}

	userInput.AppID = int(req.GetAppId())

	userID, tokenData, err := c.usecase.Login(ctx, userInput, userDevice)
	switch {
	case errors.Is(err, le.ErrPasswordsDontMatch):
		log.Error(le.ErrPasswordsDontMatch.Error(), slog.String(key.Email, userInput.Email))
		return nil, status.Error(codes.Unauthenticated, le.ErrPasswordsDontMatch.Error())
	case err != nil:
		log.Error(le.ErrInternalServerError.Error(), slog.String(key.Email, userInput.Email))
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	tokenDataResponse := &ssov1.TokenData{
		AccessToken:      tokenData.AccessToken,
		RefreshToken:     tokenData.RefreshToken,
		Domain:           tokenData.Domain,
		Path:             tokenData.Path,
		ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
		HttpOnly:         tokenData.HTTPOnly,
		AdditionalFields: tokenData.AdditionalFields,
	}

	log.Info("user and tokens created",
		slog.String(key.UserID, userID),
		slog.String(key.AccessToken, tokenData.AccessToken),
		slog.String(key.RefreshToken, tokenData.RefreshToken))

	return &ssov1.LoginResponse{TokenData: tokenDataResponse}, nil
}

func (c *authController) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	const op = "authController.Register"

	// Get request ID
	reqID, err := extractRequestID(ctx, c.log, op)
	if err != nil {
		return nil, err
	}

	log := logger.LogWithRequest(c.log, reqID, op)

	// Get user device data
	userDevice, err := extractUserDeviceData(ctx, log)
	if err != nil {
		return nil, err
	}

	// Validate request
	userInput := &model.UserRequestData{}
	if err = validateRegister(req, userInput); err != nil {
		log.Error(fmt.Sprintf("%s: %s ", le.ErrValidationFailed.Error(), err))
		return nil, err
	}

	userInput.AppID = int(req.GetAppId())

	userID, tokenData, err := c.usecase.RegisterNewUser(ctx, userInput, userDevice)
	if err != nil {
		// TODO: add checking if user already exists
		// TODO: ... Add errors descriptions
		// TODO: add logs with request details (email for example)
		return nil, status.Error(codes.Internal, le.ErrInternalServerError.Error())
	}

	tokenDataResponse := &ssov1.TokenData{
		AccessToken:      tokenData.AccessToken,
		RefreshToken:     tokenData.RefreshToken,
		Domain:           tokenData.Domain,
		Path:             tokenData.Path,
		ExpiresAt:        timestamppb.New(tokenData.ExpiresAt),
		HttpOnly:         tokenData.HTTPOnly,
		AdditionalFields: tokenData.AdditionalFields,
	}

	log.Info("user and tokens created",
		slog.String(key.UserID, userID),
		slog.String(key.AccessToken, tokenData.AccessToken),
		slog.String(key.RefreshToken, tokenData.RefreshToken))

	return &ssov1.RegisterResponse{TokenData: tokenDataResponse}, nil
}
