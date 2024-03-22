package controller

import (
	"context"
	"errors"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
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
	log     *slog.Logger
	usecase port.AuthUsecase
}

func RegisterController(gRPC *grpc.Server, log *slog.Logger, usecase port.AuthUsecase) {
	ssov1.RegisterAuthServer(gRPC, &authController{log: log, usecase: usecase})
}

func (c *authController) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	userInput := &model.UserRequestData{}
	if err := validateLogin(req, userInput); err != nil {
		return nil, err
	}

	userInput.AppID = int(req.GetAppId())

	userDevice := model.UserDeviceRequestData{
		UserAgent: req.UserDeviceData.GetUserAgent(),
		IP:        req.UserDeviceData.GetIp(),
	}

	// TODO: add other errors from usecase layer
	tokenData, err := c.usecase.Login(ctx, userInput, userDevice)
	switch {
	case errors.Is(err, le.ErrPasswordsDontMatch):
		return nil, status.Error(codes.Unauthenticated, le.ErrPasswordsDontMatch.Error())
	case err != nil:
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

	return &ssov1.LoginResponse{TokenData: tokenDataResponse}, nil
}

func (c *authController) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	userInput := &model.UserRequestData{}
	if err := validateRegister(req, userInput); err != nil {
		return nil, err
	}

	userInput.AppID = int(req.GetAppId())

	// TODO: update this part: will get userDevice from request
	//userDevice, err := c.extractUserDeviceData(ctx, userInput.Email)
	//if err != nil {
	//	return nil, err
	//}
	userDevice := model.UserDeviceRequestData{
		UserAgent: req.UserDeviceData.GetUserAgent(),
		IP:        req.UserDeviceData.GetIp(),
	}

	// TODO: add other errors from usecase layer
	tokenData, err := c.usecase.RegisterNewUser(ctx, userInput, userDevice)
	if err != nil {
		// TODO: add checking if user already exists
		// TODO: ... Add errors descriptions
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

	return &ssov1.RegisterResponse{TokenData: tokenDataResponse}, nil
}

//func (c *authController) extractUserDeviceData(ctx context.Context, email string) (model.UserDeviceRequestData, error) {
//	userDevice, err := c.usecase.ExtractUserDeviceData(ctx, email)
//	if err != nil {
//		if errors.Is(err, le.ErrUserAgentIsRequired) {
//			return model.UserDeviceRequestData{}, status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
//		} else if errors.Is(err, le.ErrIPIsRequired) {
//			return model.UserDeviceRequestData{}, status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
//		}
//		return model.UserDeviceRequestData{}, status.Error(codes.Internal, le.ErrInternalServerError.Error())
//	}
//
//	return userDevice, nil
//}
