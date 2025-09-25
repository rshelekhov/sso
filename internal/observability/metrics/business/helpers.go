package business

import "go.opentelemetry.io/otel/metric"

func createCounter(meter metric.Meter, name, description, unit string) (metric.Int64Counter, error) {
	return meter.Int64Counter(name,
		metric.WithDescription(description),
		metric.WithUnit(unit))
}

func createUpDownCounter(meter metric.Meter, name, description, unit string) (metric.Int64UpDownCounter, error) {
	return meter.Int64UpDownCounter(name,
		metric.WithDescription(description),
		metric.WithUnit(unit))
}

func createHistogram(meter metric.Meter, name, description, unit string) (metric.Float64Histogram, error) {
	return meter.Float64Histogram(name,
		metric.WithDescription(description),
		metric.WithUnit(unit))
}
