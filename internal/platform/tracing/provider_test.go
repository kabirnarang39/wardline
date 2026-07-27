package tracing_test

import (
	"context"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/tracing"
)

func TestNewDisabled_ProducesInvalidSpans(t *testing.T) {
	p := tracing.NewDisabled()
	_, span := p.Tracer().Start(context.Background(), "test-span")
	defer span.End()

	if span.SpanContext().IsValid() {
		t.Error("expected a no-op tracer's span to be invalid (tracing disabled)")
	}
}

func TestNewDisabled_ShutdownIsSafe(t *testing.T) {
	p := tracing.NewDisabled()
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("expected Shutdown on a disabled provider to be a no-op, got error: %v", err)
	}
}

func TestNewOTLPHTTP_ConstructsSuccessfully(t *testing.T) {
	// otlptracehttp.New does not connect on construction — it only builds
	// the client, so a syntactically valid endpoint that nothing is
	// listening on still constructs without error.
	p, err := tracing.NewOTLPHTTP(context.Background(), "wardline-test", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Shutdown(context.Background()) }()

	_, span := p.Tracer().Start(context.Background(), "test-span")
	defer span.End()

	if !span.SpanContext().IsValid() {
		t.Error("expected a real SDK tracer's span to be valid")
	}
}
