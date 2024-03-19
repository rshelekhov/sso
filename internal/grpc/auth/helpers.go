package auth

import (
	"context"
	"fmt"
	ssov1 "github.com/rshelekhov/sso-protos/gen/go/sso"
	"github.com/rshelekhov/sso/internal/lib/constants/le"
	"github.com/rshelekhov/sso/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
)

func extractRequestID(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", le.ErrFailedToExtractMetaData
	}

	var requestID string
	if len(md["request-id"]) > 0 {
		requestID = md["request-id"][0]
	} else {
		return "", le.ErrRequestIDIsRequired
	}

	return requestID, nil
}

func extractUserDeviceData(ctx context.Context) (model.UserDeviceRequestData, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return model.UserDeviceRequestData{}, le.ErrFailedToExtractMetaData
	}

	var userAgent, ip string

	if len(md["user-agent"]) > 0 {
		userAgent = md["user-agent"][0]
	} else {
		return model.UserDeviceRequestData{}, le.ErrUserAgentIsRequired
	}

	if len(md["ip"]) > 0 {
		ipParts := strings.Split(md["ip"][0], ":")
		ip = ipParts[0]
	} else {
		return model.UserDeviceRequestData{}, le.ErrIPIsRequired
	}

	return model.UserDeviceRequestData{
		UserAgent: userAgent,
		IP:        ip,
	}, nil
}

func validateLogin(req *ssov1.LoginRequest) error {
	// TODO: add validation with validator
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, fmt.Sprint(le.ErrEmailIsRequired))
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, fmt.Sprint(le.ErrPasswordIsRequired))
	}

	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, fmt.Sprint(le.ErrAppIDIsRequired))
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	// TODO: add validation with validator
	if req.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}

	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	return nil
}
