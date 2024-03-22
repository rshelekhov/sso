package auth

import (
	"context"
	"fmt"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/lib/logger"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
)

const emptyValue = 0

func extractRequestID(ctx context.Context, log logger.Interface, op string) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Error(fmt.Sprintf("%s: %s", op, le.ErrFailedToExtractMetaData))
		return "", status.Error(codes.Internal, le.ErrFailedToExtractMetaData.Error())
	}

	var requestID string
	if len(md["request-id"]) > 0 {
		requestID = md["request-id"][0]
	} else {
		log.Error(fmt.Sprintf("%s: %s", op, le.ErrRequestIDIsRequired))
		return "", status.Error(codes.InvalidArgument, le.ErrRequestIDIsRequired.Error())
	}

	return requestID, nil
}

func extractUserDeviceData(ctx context.Context, log logger.Interface) (model.UserDeviceRequestData, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Error(le.ErrFailedToExtractMetaData.Error())
		return model.UserDeviceRequestData{}, status.Error(codes.Internal, le.ErrFailedToExtractMetaData.Error())
	}

	var userAgent, ip string

	if len(md["user-agent"]) > 0 {
		userAgent = md["user-agent"][0]
	} else {
		log.Error(le.ErrUserAgentIsRequired.Error())
		return model.UserDeviceRequestData{}, status.Error(codes.InvalidArgument, le.ErrUserAgentIsRequired.Error())
	}

	if len(md["ip"]) > 0 {
		ipParts := strings.Split(md["ip"][0], ":")
		ip = ipParts[0]
	} else {
		log.Error(le.ErrIPIsRequired.Error())
		return model.UserDeviceRequestData{}, status.Error(codes.InvalidArgument, le.ErrIPIsRequired.Error())
	}

	return model.UserDeviceRequestData{
		UserAgent: userAgent,
		IP:        ip,
	}, nil
}

func validateLogin(req *ssov1.LoginRequest, userInput *model.UserRequestData) error {
	// TODO: add validation with validator
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
		return status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	userInput = &model.UserRequestData{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}

	return nil
}
