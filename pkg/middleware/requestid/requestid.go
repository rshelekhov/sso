package requestid

import (
	"net/http"

	"github.com/rshelekhov/sso/pkg/middleware"
	"github.com/segmentio/ksuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type manager struct{}

func NewManager() middleware.Manager {
	return &manager{}
}

const (
	Header = "X-Request-ID"
	CtxKey = "RequestID"
)

// NewID returns new requestID
func (m *manager) NewID() string {
	return ksuid.New().String()
}

// FromContext returns requestID from context
func (m *manager) FromContext(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(CtxKey).(string)
	return requestID, ok
}

// ToContext places requestID to context
func (m *manager) ToContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, CtxKey, requestID)
}

// ExtractFromGRPC returns requestID from gRPC metadata or generates new one
func (m *manager) ExtractFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return m.NewID(), nil
	}

	values := md.Get(Header)
	if len(values) == 0 {
		return m.NewID(), nil
	}

	return values[0], nil
}

// ExtractFromHTTP returns requestID from HTTP header or generates new one
func (m *manager) ExtractFromHTTP(r *http.Request) (string, error) {
	requestID := r.Header.Get(Header)
	if requestID == "" {
		return m.NewID(), nil
	}

	return requestID, nil
}

// UnaryServerInterceptor extract requestID from gRPC metadata and set it to context
func (m *manager) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID, _ := m.ExtractFromGRPC(ctx)
		ctx = m.ToContext(ctx, requestID)

		return handler(ctx, req)
	}
}

// HTTPMiddleware extract requestID from HTTP header and set it to context
func (m *manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, _ := m.ExtractFromHTTP(r)
		ctx := m.ToContext(r.Context(), requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
