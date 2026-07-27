package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Provider wraps the tracer this process uses and how to shut it down
// cleanly. When tracing is disabled, Tracer returns a no-op
// implementation — every span operation becomes a cheap no-op, so callers
// (Handler) don't need their own enabled/disabled branching.
type Provider struct {
	tracer   trace.Tracer
	shutdown func(context.Context) error
}

// NewDisabled returns a Provider backed by a no-op tracer — used when the
// otel_tracing feature flag is off.
func NewDisabled() *Provider {
	return &Provider{
		tracer:   noop.NewTracerProvider().Tracer("wardline"),
		shutdown: func(context.Context) error { return nil },
	}
}

// NewOTLPHTTP builds a Provider exporting spans via OTLP/HTTP to endpoint
// (host:port, e.g. "localhost:4318" — no scheme; plaintext HTTP, matching
// how local/dev OTel collectors are commonly run). serviceName identifies
// this process in the trace backend. Also installs the W3C trace-context
// propagator process-wide, so incoming traceparent headers get extracted.
func NewOTLPHTTP(ctx context.Context, serviceName, endpoint string) (*Provider, error) {
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTextMapPropagator(propagation.TraceContext{})

	return &Provider{
		tracer:   tp.Tracer("wardline"),
		shutdown: tp.Shutdown,
	}, nil
}

// Tracer returns the tracer to start spans with.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Shutdown flushes any buffered spans and releases resources. Safe to call
// on a disabled Provider (no-op).
func (p *Provider) Shutdown(ctx context.Context) error {
	return p.shutdown(ctx)
}
