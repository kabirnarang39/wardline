package adapter

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

var transportTestLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type discardWriter struct{}

func (discardWriter) Write(auditdomain.Entry) error { return nil }

type allowEngine struct{}

func (allowEngine) Evaluate(policydomain.Context) policydomain.Decision {
	return policydomain.Decision{Effect: policydomain.EffectAllow}
}

type allowBudget struct{}

func (allowBudget) Check(string, string, string, time.Time) budgetdomain.Verdict {
	return budgetdomain.Verdict{Allowed: true}
}

// TestNewHandler_TunesMaxIdleConnsPerHost proves the upstream transport
// doesn't run with http.Transport's default MaxIdleConnsPerHost of 2 --
// under concurrent load against one upstream host (Wardline's whole job),
// that default starves connection reuse down to 2 pooled connections and
// forces a fresh dial+handshake per request past trivial concurrency,
// measured at a ~5x throughput regression in bench/run.sh's max-rate
// scenario before this was tuned. See handler.go's
// upstreamMaxIdleConnsPerHost comment for the full explanation.
func TestNewHandler_TunesMaxIdleConnsPerHost(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:0")
	recorder := auditusecase.NewRecorder(discardWriter{}, nil, nil)
	decider := proxyusecase.NewDecider(allowEngine{})
	h := NewHandler(decider, recorder, upstreamURL, allowBudget{}, noop.NewTracerProvider().Tracer(""), HeaderIdentity{}, transportTestLogger, nil, "", nil)

	tr, ok := h.upstream.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", h.upstream.Transport)
	}
	if tr.MaxIdleConnsPerHost != upstreamMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d (http.Transport's own default of 2 throttles concurrent single-upstream throughput)",
			tr.MaxIdleConnsPerHost, upstreamMaxIdleConnsPerHost)
	}
}
