package metrics

import (
	"context"
	"time"

	"github.com/rshelekhov/sso/internal/lib/interceptor"
	"github.com/rshelekhov/sso/internal/lib/interceptor/clientid"
	"github.com/rshelekhov/sso/internal/observability/metrics/infrastructure"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type Interceptor struct {
	metrics *infrastructure.GRPCServerMetrics
}

func NewInterceptor(metrics *infrastructure.GRPCServerMetrics) *Interceptor {
	return &Interceptor{metrics: metrics}
}

// UnaryServerInterceptor creates a gRPC unary server interceptor for collecting metrics.
//
// IMPORTANT: This interceptor should be registered FIRST in the interceptor chain
// (which means LAST when using grpc.ChainUnaryInterceptor) to measure the total
// request processing time including all other interceptors.
//
// Example:
//
//	grpc.ChainUnaryInterceptor(
//	    requestid.UnaryServerInterceptor(),
//	    auth.UnaryServerInterceptor(),
//	    metrics.UnaryServerInterceptor(metricsInstance), // LAST = FIRST in chain
//	)
func (i *Interceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		start := time.Now()
		service, method := interceptor.SplitMethod(info.FullMethod)

		i.metrics.ActiveConnections.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", service),
			attribute.String("method", method),
		))

		defer func() {
			i.metrics.ActiveConnections.Add(ctx, -1, metric.WithAttributes(
				attribute.String("service", service),
				attribute.String("method", method),
			))
		}()

		resp, err = handler(ctx, req)

		code := status.Code(err).String()
		elapsed := time.Since(start)

		i.metrics.Requests.Add(ctx, 1, metric.WithAttributes(
			attribute.String("service", service),
			attribute.String("method", method),
			attribute.String("code", code),
		))

		i.metrics.Duration.Record(ctx, elapsed.Milliseconds(), metric.WithAttributes(
			attribute.String("service", service),
			attribute.String("method", method),
			attribute.String("code", code),
		))

		if reqProto, ok := req.(proto.Message); ok {
			i.metrics.RequestSize.Record(ctx, int64(proto.Size(reqProto)), metric.WithAttributes(
				attribute.String("service", service),
				attribute.String("method", method),
				attribute.String("code", code),
			))
		}

		if respProto, ok := resp.(proto.Message); ok {
			i.metrics.ResponseSize.Record(ctx, int64(proto.Size(respProto)), metric.WithAttributes(
				attribute.String("service", service),
				attribute.String("method", method),
				attribute.String("code", code),
			))
		}

		if clientID, ok := clientid.FromContext(ctx); ok {
			i.metrics.APIUsageByClient.Add(ctx, 1, metric.WithAttributes(
				attribute.String("client_id", clientID),
				attribute.String("service", service),
				attribute.String("method", method),
				attribute.String("code", code),
			))
		}

		return resp, err
	}
}
