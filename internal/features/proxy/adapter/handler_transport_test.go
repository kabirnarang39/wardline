package adapter

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// blockingReadCloser's Read hangs forever -- standing in for a real SSE
// upstream that has sent its headers but not yet enough body to reach
// readResponseSignal's 8 KiB cap or EOF. If readResponseSignal ever
// calls Read on an SSE response's body, this deadlocks the test (caught
// by `go test`'s own timeout) rather than passing silently.
type blockingReadCloser struct{}

func (blockingReadCloser) Read([]byte) (int, error) {
	select {}
}

func (blockingReadCloser) Close() error { return nil }

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

// TestReadResponseSignal_SSEResponseNeverBlocksOnBody proves the fix for
// a real bug: a streaming (Server-Sent Events) MCP response body is
// never read here. blockingReadCloser's Read hangs forever, standing in
// for a real SSE upstream that has sent headers but hasn't yet produced
// 8 KiB of body or closed the stream (a long-running tool call
// trickling small events, exactly MCP's own Streamable HTTP transport
// shape) -- if readResponseSignal ever called Read on it, this test
// would hang instead of returning promptly.
func TestReadResponseSignal_SSEResponseNeverBlocksOnBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       blockingReadCloser{},
	}

	done := make(chan struct{})
	go func() {
		readResponseSignal(resp)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readResponseSignal blocked reading a streaming (text/event-stream) response body instead of returning immediately")
	}
}

// TestReadResponseSignal_NonStreamingResponseStillExtractsSignal proves
// the fix above is scoped to Content-Type: text/event-stream only --
// an ordinary (non-streaming) JSON-RPC response must still get its
// no-op/error signal extracted exactly as before.
func TestReadResponseSignal_NonStreamingResponseStillExtractsSignal(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"result":{"isError":true}}`)),
	}

	sig := readResponseSignal(resp)
	if !sig.NoOpSignal {
		t.Error("expected NoOpSignal true for a result.isError:true body, got false")
	}
}
