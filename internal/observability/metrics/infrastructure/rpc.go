package infrastructure

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
)

const (
	// gRPC metrics
	MetricRPCServerRequests         = "rpc.server.requests"
	MetricRPCServerActiveConns      = "rpc.server.active_connections"
	MetricRPCServerDuration         = "rpc.server.duration"
	MetricRPCServerRequestSize      = "rpc.server.request.size"
	MetricRPCServerResponseSize     = "rpc.server.response.size"
	MetricRPCServerAPIUsageByClient = "rpc.server.api.usage.by_client"
)

type GRPCServerMetrics struct {
	Requests          metric.Int64Counter
	ActiveConnections metric.Int64UpDownCounter
	Duration          metric.Int64Histogram
	RequestSize       metric.Int64Histogram
	ResponseSize      metric.Int64Histogram
	APIUsageByClient  metric.Int64Counter
}

func NewGRPCServerMetrics(meter metric.Meter) (*GRPCServerMetrics, error) {
	rpcRequests, err := meter.Int64Counter(
		MetricRPCServerRequests,
		metric.WithDescription("Total number of RPC requests received by the server"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRPCServerRequests, err)
	}

	rpcActiveConnections, err := meter.Int64UpDownCounter(
		MetricRPCServerActiveConns,
		metric.WithDescription("Number of active RPC connections"),
		metric.WithUnit("{connection}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRPCServerActiveConns, err)
	}

	rpcServerDuration, err := meter.Int64Histogram(
		MetricRPCServerDuration,
		metric.WithDescription("Duration of RPC requests"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricRPCServerDuration, err)
	}

	rpcServerRequestSize, err := meter.Int64Histogram(
		MetricRPCServerRequestSize,
		metric.WithDescription("Size of RPC request messages"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricRPCServerRequestSize, err)
	}

	rpcServerResponseSize, err := meter.Int64Histogram(
		MetricRPCServerResponseSize,
		metric.WithDescription("Size of RPC response messages"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", MetricRPCServerResponseSize, err)
	}

	rpcServerAPIUsageByClient, err := meter.Int64Counter(
		MetricRPCServerAPIUsageByClient,
		metric.WithDescription("Number of API usage by client"),
		metric.WithUnit("{usage}"),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", MetricRPCServerAPIUsageByClient, err)
	}

	return &GRPCServerMetrics{
		Requests:          rpcRequests,
		ActiveConnections: rpcActiveConnections,
		Duration:          rpcServerDuration,
		RequestSize:       rpcServerRequestSize,
		ResponseSize:      rpcServerResponseSize,
		APIUsageByClient:  rpcServerAPIUsageByClient,
	}, nil
}
