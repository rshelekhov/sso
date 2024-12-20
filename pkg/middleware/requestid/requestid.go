package middleware

import (
	"github.com/segmentio/ksuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net/http"
)

type requestIDMgr struct{}

func NewRequestIDManager() Manager {
	return &requestIDMgr{}
}

const HeaderKey = "X-Request-ID"

// NewID returns new request ID
func (m *requestIDMgr) NewID() string {
	return ksuid.New().String()
}

// FromContext returns request ID from context
func (m *requestIDMgr) FromContext(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(HeaderKey).(string)
	return requestID, ok
}

// ToContext returns context with request ID
func (m *requestIDMgr) ToContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, HeaderKey, requestID)
}

// ExtractFromGRPC returns request ID from gRPC metadata or generates new one
func (m *requestIDMgr) ExtractFromGRPC(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return m.NewID(), nil
	}

	values := md.Get(HeaderKey)
	if len(values) == 0 {
		return m.NewID(), nil
	}

	return values[0], nil
}

// ExtractFromHTTP returns request ID from HTTP header or generates new one
func (m *requestIDMgr) ExtractFromHTTP(r *http.Request) (string, error) {
	requestID := r.Header.Get(HeaderKey)
	if requestID == "" {
		return m.NewID(), nil
	}

	return requestID, nil
}

// UnaryServerInterceptor create gRPC interceptor for request ID
func (m *requestIDMgr) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID, _ := m.ExtractFromGRPC(ctx)
		ctx = context.WithValue(ctx, HeaderKey, requestID)

		return handler(ctx, req)
	}
}

func (m *requestIDMgr) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, _ := m.ExtractFromHTTP(r)
		ctx := context.WithValue(r.Context(), HeaderKey, requestID)
		w.Header().Set(HeaderKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
