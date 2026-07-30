package adapter

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
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

// TestHandler_SlowUpstreamTimesOut proves a connected-but-silent upstream
// (accepts the request, never writes a response in time) gets cut off by
// ResponseHeaderTimeout instead of hanging the request indefinitely.
//
// It builds a Handler directly (rather than via NewHandler) so it can use a
// short ResponseHeaderTimeout instead of the production 30s constant,
// keeping the test fast.
func TestHandler_SlowUpstreamTimesOut(t *testing.T) {
	const testTimeout = 50 * time.Millisecond

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * testTimeout) // longer than testTimeout, but finite so Close() doesn't hang
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.Transport = &http.Transport{ResponseHeaderTimeout: testTimeout}

	writer := &fakeTimeoutWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeTimeoutEngine{effect: policydomain.EffectAllow})
	handler := &Handler{decider: decider, recorder: recorder, upstream: proxy, budgetChecker: alwaysAllowTimeoutBudgetChecker{}, identityAuth: HeaderIdentity{}, tracer: noop.NewTracerProvider().Tracer("test"), logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now}

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	w := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if elapsed >= 5*testTimeout {
		t.Fatalf("expected request to return well before upstream's sleep, took %s", elapsed)
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
}

type fakeTimeoutEngine struct {
	effect policydomain.Effect
}

func (f fakeTimeoutEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	return policydomain.Decision{Effect: f.effect, Reason: "fake"}
}

type alwaysAllowTimeoutBudgetChecker struct{}

func (alwaysAllowTimeoutBudgetChecker) Check(identity, tenant string, now time.Time) budgetdomain.Verdict {
	return budgetdomain.Verdict{Allowed: true, Reason: "budget checks not under test"}
}

type fakeTimeoutWriter struct {
	entries []auditdomain.Entry
}

func (f *fakeTimeoutWriter) Write(e auditdomain.Entry) error {
	f.entries = append(f.entries, e)
	return nil
}
