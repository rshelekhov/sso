package controller

import (
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const emptyValue = 0

func validateLogin(req *ssov1.LoginRequest, userInput *model.UserRequestData) error {
	// TODO: add validation with validator
	// TODO: check if have a possibility to return a list of errors
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, le.ErrEmailIsRequired.Error())
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, le.ErrAppIDIsRequired.Error())
	}

	userInput = &model.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest, userInput *model.UserRequestData) error {
	// TODO: add validation with validator
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, le.ErrEmailIsRequired.Error())
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, le.ErrPasswordIsRequired.Error())
	}

	userInput = &model.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	return nil
}
