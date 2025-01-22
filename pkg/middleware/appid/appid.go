package appid

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rshelekhov/sso/pkg/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type manager struct{}

func NewManager() middleware.Manager {
	return &manager{}
}

const (
	Header = "X-App-ID"
	CtxKey = "AppID"
)

// FromContext returns appID from context
func (m *manager) FromContext(ctx context.Context) (string, bool) {
	appID, ok := ctx.Value(CtxKey).(string)
	return appID, ok
}

// ToContext returns context with appID
func (m *manager) ToContext(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, CtxKey, appID)
}

// ExtractFromGRPC returns appID from gRPC metadata
func (m *manager) ExtractFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no gRPC metadata")
	}

	values := md.Get(Header)
	if len(values) == 0 {
		return "", fmt.Errorf("appID not found in gRPC metadata")
	}

	return values[0], nil
}

// ExtractFromHTTP returns appID from HTTP header or generates new one
func (m *manager) ExtractFromHTTP(r *http.Request) (string, error) {
	appID := r.Header.Get(Header)
	if appID == "" {
		return "", fmt.Errorf("appID header not found in HTTP request")
	}

	return appID, nil
}

// UnaryServerInterceptor extract appID from gRPC metadata and set it to context
func (m *manager) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		appID, err := m.ExtractFromGRPC(ctx)
		if err != nil {
			return nil, err
		}

		ctx = m.ToContext(ctx, appID)

		return handler(ctx, req)
	}
}

// HTTPMiddleware extract appID from HTTP header and set it to context
func (m *manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appID, err := m.ExtractFromHTTP(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := m.ToContext(r.Context(), appID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
