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
	userData := &model.UserRequestData{}
	if err := validateLoginData(req, userData); err != nil {
		return nil, err
	}

	// TODO: add other errors from usecase layer
	tokenData, err := c.usecase.Login(ctx, userData)
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
	userData := &model.UserRequestData{}
	if err := validateRegisterData(req, userData); err != nil {
		return nil, err
	}

	// TODO: add other errors from usecase layer
	tokenData, err := c.usecase.RegisterNewUser(ctx, userData)
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

func (c *authController) Refresh(ctx context.Context, req *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	request := &model.RefreshRequestData{}
	if err := validateRefresh(req, request); err != nil {
		return nil, err
	}

	// TODO: add other errors from usecase layer
	tokenData, err := c.usecase.RefreshTokens(ctx, request)
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

	return &ssov1.RefreshResponse{TokenData: tokenDataResponse}, nil
}
