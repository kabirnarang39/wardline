package adapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// jsonRPCErrorEnvelope mirrors the shape written by writeJSONRPCError, for
// asserting on error response bodies from outside the package.
type jsonRPCErrorEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeJSONRPCError(t *testing.T, w *httptest.ResponseRecorder) jsonRPCErrorEnvelope {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
	var env jsonRPCErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body: %s)", err, w.Body.String())
	}
	if env.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", env.JSONRPC)
	}
	return env
}

type fakeEngine struct {
	effect policydomain.Effect
	reason string
}

func (f fakeEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	reason := f.reason
	if reason == "" {
		reason = "fake"
	}
	return policydomain.Decision{Effect: f.effect, Reason: reason}
}

type fakeWriter struct {
	entries []auditdomain.Entry
}

func (f *fakeWriter) Write(e auditdomain.Entry) error {
	f.entries = append(f.entries, e)
	return nil
}

// alwaysAllowBudgetChecker is a no-op BudgetChecker for tests that aren't
// exercising budget behavior — every call is allowed.
type alwaysAllowBudgetChecker struct{}

func (alwaysAllowBudgetChecker) Check(identity string, now time.Time) budgetdomain.Verdict {
	return budgetdomain.Verdict{Allowed: true, Reason: "budget checks not under test"}
}

var noopTracer = noop.NewTracerProvider().Tracer("test")

// testLogger discards output — tests assert behavior, not log lines, and a
// live logger would just print noise during `go test -v`.
var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type contextRecordingEngine struct {
	received policydomain.Context
}

func (e *contextRecordingEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	e.received = ctx
	return policydomain.Decision{Effect: policydomain.EffectAllow, Reason: "fake"}
}

func newRequest(identity, tool string) *http.Request {
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + tool + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("X-Wardline-Identity", identity)
	return req
}

func TestHandler_AllowedCallReachesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
}

// TestHandler_AuthorizationHeaderStrippedBeforeForwarding proves the bearer
// credential a caller authenticated to Wardline with is never forwarded to
// the untrusted upstream MCP server. httputil.ReverseProxy does not strip
// Authorization on its own (it's not a hop-by-hop header) — without an
// explicit strip in forward(), a malicious/compromised upstream could
// harvest a live, replayable Wardline credential from every proxied call.
func TestHandler_AuthorizationHeaderStrippedBeforeForwarding(t *testing.T) {
	var gotAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	req := newRequest("agent-abc123", "read_file")
	req.Header.Set("Authorization", "Bearer some-live-wardline-credential")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotAuthorization != "" {
		t.Errorf("expected the upstream to never see an Authorization header, got %q", gotAuthorization)
	}
}

func TestHandler_DeniedCallNeverReachesUpstream(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	const sensitiveReason = "policy evaluation failed: /etc/wardline/policy.rego:12: internal detail"

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectDeny, reason: sensitiveReason})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream should not have been called for a denied request")
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "deny" {
		t.Fatalf("expected one deny audit entry, got %+v", writer.entries)
	}
	if writer.entries[0].Reason != sensitiveReason {
		t.Errorf("expected the audit log to capture the detailed reason %q, got %q", sensitiveReason, writer.entries[0].Reason)
	}
	env := decodeJSONRPCError(t, w)
	if env.Error.Message == "" {
		t.Error("expected a non-empty error message")
	}
	if env.Error.Message != "denied by policy" {
		t.Errorf("expected a generic deny message, got %q", env.Error.Message)
	}
	if strings.Contains(env.Error.Message, sensitiveReason) {
		t.Error("response body must never contain the detailed policy reason")
	}
}

func TestHandler_UpstreamUnreachableReturnsError(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1") // nothing listens here

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
	decodeJSONRPCError(t, w)
}

func TestHandler_MalformedBodyReturnsError(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("not json"))
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
	env := decodeJSONRPCError(t, w)
	if string(env.ID) != "null" {
		t.Errorf("expected null id for unparsable body, got %s", env.ID)
	}
}

func TestHandler_ToolCallParseErrorEchoesRealID(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	// Well-formed envelope with a real id, but malformed tools/call params
	// (a string instead of an object) — the id is fully recoverable, so
	// the error response must echo it back rather than "null".
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":"oops"}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	env := decodeJSONRPCError(t, w)
	if string(env.ID) != "7" {
		t.Errorf("expected id 7 to be echoed back, got %s", env.ID)
	}
}

func TestHandler_OversizedBodyRejected(t *testing.T) {
	upstreamURL, _ := url.Parse("http://127.0.0.1:1")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	// One byte over the 1 MiB cap; content doesn't matter since the reader
	// should be cut off before the body is parsed as JSON.
	oversized := bytes.Repeat([]byte("a"), (1<<20)+1)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(oversized))
	req.Header.Set("X-Wardline-Identity", "agent-abc123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "error" {
		t.Fatalf("expected one error audit entry, got %+v", writer.entries)
	}
	decodeJSONRPCError(t, w)
}

func TestHandler_PopulatesContextFromRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	engine := &contextRecordingEngine{}
	decider := proxyusecase.NewDecider(engine)
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	before := time.Now()
	req := newRequest("agent-abc123", "read_file")
	req.Header.Set("User-Agent", "wardline-test-agent/1.0")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	after := time.Now()

	if engine.received.Identity != "agent-abc123" {
		t.Errorf("expected Identity to be forwarded, got %q", engine.received.Identity)
	}
	if engine.received.Tool != "read_file" {
		t.Errorf("expected Tool to be forwarded, got %q", engine.received.Tool)
	}
	if string(engine.received.Params) != `{"name":"read_file"}` {
		t.Errorf("expected Params to be forwarded unchanged, got %q", engine.received.Params)
	}
	if engine.received.RemoteAddr != req.RemoteAddr {
		t.Errorf("expected RemoteAddr %q, got %q", req.RemoteAddr, engine.received.RemoteAddr)
	}
	if engine.received.UserAgent != "wardline-test-agent/1.0" {
		t.Errorf("expected UserAgent to be forwarded, got %q", engine.received.UserAgent)
	}
	if engine.received.Timestamp.Before(before) || engine.received.Timestamp.After(after) {
		t.Errorf("expected Timestamp between %v and %v, got %v", before, after, engine.received.Timestamp)
	}
}

type fakeBudgetChecker struct {
	verdict budgetdomain.Verdict
}

func (f fakeBudgetChecker) Check(identity string, now time.Time) budgetdomain.Verdict {
	return f.verdict
}

func TestHandler_ThrottledCallNeverReachesUpstream(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	const throttleReason = "rate limit exceeded: 1 requests per 1m0s window"

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	budgetChecker := fakeBudgetChecker{verdict: budgetdomain.Verdict{Allowed: false, Reason: throttleReason, RetryAfter: 45 * time.Second}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream should not have been called for a throttled request")
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "throttled" {
		t.Fatalf("expected one throttled audit entry, got %+v", writer.entries)
	}
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected a Retry-After header on a 429 response")
	}
	if seconds, err := strconv.Atoi(retryAfter); err != nil || seconds <= 0 {
		t.Errorf("expected Retry-After to be a positive integer, got %q", retryAfter)
	}
	if writer.entries[0].Reason != throttleReason {
		t.Errorf("expected the audit log to capture the detailed reason %q, got %q", throttleReason, writer.entries[0].Reason)
	}
	env := decodeJSONRPCError(t, w)
	if env.Error.Message != "throttled by budget" {
		t.Errorf("expected a generic throttle message, got %q", env.Error.Message)
	}
	if strings.Contains(env.Error.Message, throttleReason) {
		t.Error("response body must never contain the detailed budget reason")
	}
}

func TestHandler_AllowedByBudgetReachesUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	budgetChecker := fakeBudgetChecker{verdict: budgetdomain.Verdict{Allowed: true, Reason: "within budget"}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
}

func TestHandler_DeniedByPolicyNeverConsultsBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectDeny})
	// A budget checker that would deny everything, proving a policy deny
	// short-circuits before budget is ever consulted (the audit decision
	// must be "deny", not "throttled").
	budgetChecker := fakeBudgetChecker{verdict: budgetdomain.Verdict{Allowed: false, Reason: "should never be seen"}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (policy deny), got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "deny" {
		t.Fatalf("expected one deny audit entry (not throttled), got %+v", writer.entries)
	}
}

func TestHandler_PropagatesIncomingTraceID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	tracer := tp.Tracer("test")

	// In production, tracing.NewOTLPHTTP installs the W3C trace-context
	// propagator process-wide once at startup (see internal/platform/tracing).
	// Replicate that here so Extract has something to extract with, and
	// restore the prior global propagator so this test doesn't leak state
	// into others.
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(prevPropagator)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, tracer, adapter.HeaderIdentity{}, testLogger, nil)

	req := newRequest("agent-abc123", "read_file")
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Read spans before Shutdown — Shutdown resets the in-memory exporter's
	// stored spans, so a read-after-shutdown would silently see zero spans.
	spans := exporter.GetSpans()
	_ = tp.Shutdown(context.Background())

	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].SpanContext.TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected the span to be a child of the incoming trace ID, got %q", spans[0].SpanContext.TraceID().String())
	}
	if len(writer.entries) != 1 || writer.entries[0].TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected the audit entry's TraceID to match, got %+v", writer.entries)
	}
}

func TestHandler_DeniedCallSetsErrorSpanStatus(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	tracer := tp.Tracer("test")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectDeny, reason: "some reason"})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, tracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))

	// Read spans before Shutdown — Shutdown resets the in-memory exporter's
	// stored spans, so a read-after-shutdown would silently see zero spans.
	spans := exporter.GetSpans()
	_ = tp.Shutdown(context.Background())

	if upstreamHit {
		t.Fatal("upstream should not have been called for a denied request")
	}
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Errorf("expected span status Error for a denied call, got %v", spans[0].Status.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].TraceID == "" {
		t.Errorf("expected a non-empty audit entry TraceID, got %+v", writer.entries)
	}
}

func TestHandler_ThrottledCallSetsErrorSpanStatus(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	tracer := tp.Tracer("test")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	budgetChecker := fakeBudgetChecker{verdict: budgetdomain.Verdict{Allowed: false, Reason: "rate limit exceeded"}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, tracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	// Read spans before Shutdown — Shutdown resets the in-memory exporter's
	// stored spans, so a read-after-shutdown would silently see zero spans.
	spans := exporter.GetSpans()
	_ = tp.Shutdown(context.Background())

	if upstreamHit {
		t.Fatal("upstream should not have been called for a throttled request")
	}
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Errorf("expected span status Error for a throttled call, got %v", spans[0].Status.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].TraceID == "" {
		t.Errorf("expected a non-empty audit entry TraceID, got %+v", writer.entries)
	}
}

// countingEngine wraps fakeEngine and counts Evaluate calls, so a test
// can assert policy was never consulted for a passthrough request.
type countingEngine struct {
	fakeEngine
	calls int
}

func (e *countingEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	e.calls++
	return e.fakeEngine.Evaluate(ctx)
}

// countingBudgetChecker counts Check calls, so a test can assert budget
// was never consulted for a passthrough request.
type countingBudgetChecker struct {
	calls int
}

func (c *countingBudgetChecker) Check(identity string, now time.Time) budgetdomain.Verdict {
	c.calls++
	return budgetdomain.Verdict{Allowed: true, Reason: "not under test"}
}

func TestHandler_PassthroughRequest_SkipsPolicyAndBudget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	engine := &countingEngine{fakeEngine: fakeEngine{effect: policydomain.EffectDeny}}
	budget := &countingBudgetChecker{}
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(engine)
	h := adapter.NewHandler(decider, recorder, upstreamURL, budget, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Wardline-Identity", "agent-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if engine.calls != 0 {
		t.Errorf("expected policy engine to never be consulted for a passthrough request, got %d calls", engine.calls)
	}
	if budget.calls != 0 {
		t.Errorf("expected budget checker to never be consulted for a passthrough request, got %d calls", budget.calls)
	}
	if len(writer.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(writer.entries))
	}
	entry := writer.entries[0]
	if entry.Decision != "passthrough" {
		t.Errorf("expected decision %q, got %q", "passthrough", entry.Decision)
	}
	if entry.Tool != "initialize" {
		t.Errorf("expected Tool to hold the method name %q, got %q", "initialize", entry.Tool)
	}
}

func TestHandler_PassthroughRequest_SpanStatusStaysOK(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	tracer := tp.Tracer("test")

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectDeny})
	h := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, tracer, adapter.HeaderIdentity{}, testLogger, nil)

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Wardline-Identity", "agent-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Status.Code == codes.Error {
		t.Errorf("expected passthrough success to NOT set span status to Error, got %v (%s)", spans[0].Status.Code, spans[0].Status.Description)
	}
}

func TestHandler_TraceIDEmptyWhenTracingDisabled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if len(writer.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(writer.entries))
	}
	if writer.entries[0].TraceID != "" {
		t.Errorf("expected empty TraceID when tracing is disabled, got %q", writer.entries[0].TraceID)
	}
}

type failingIdentityAuth struct{}

func (failingIdentityAuth) Authenticate(r *http.Request) (string, string, error) {
	return "", "", errors.New("simulated auth failure")
}

func TestHandler_FailedIdentityAuthNeverReachesDeciderBudgetOrRecorder(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, failingIdentityAuth{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream should not have been called when identity authentication fails")
	}
	if len(writer.entries) != 0 {
		t.Fatalf("expected zero audit entries for a failed authentication, got %d", len(writer.entries))
	}
}

func TestHandler_SuccessfulIdentityAuthProceedsNormally(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.NewBearerIdentity(fakeSucceedingAuthenticator{identity: "agent-abc123"}), testLogger, nil)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file"}}`))
	req.Header.Set("Authorization", "Bearer some-valid-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if len(writer.entries) != 1 || writer.entries[0].Identity != "agent-abc123" {
		t.Fatalf("expected one audit entry for agent-abc123, got %+v", writer.entries)
	}
}

type fakeSucceedingAuthenticator struct {
	identity string
}

func (f fakeSucceedingAuthenticator) Authenticate(bearerToken string) (string, string, error) {
	return f.identity, "", nil
}

// fakeAutoBlockChecker is a stub AutoBlockChecker returning a fixed verdict,
// mirroring fakeBudgetChecker's shape.
type fakeAutoBlockChecker struct {
	verdict anomalydomain.BlockVerdict
}

func (f fakeAutoBlockChecker) Check(identity string, now time.Time) anomalydomain.BlockVerdict {
	return f.verdict
}

// panickingEngine fails the test immediately if Evaluate is ever called —
// used to prove the auto-block gate short-circuits before policy evaluation,
// not just before forwarding to upstream.
type panickingEngine struct {
	t *testing.T
}

func (p panickingEngine) Evaluate(ctx policydomain.Context) policydomain.Decision {
	p.t.Fatal("policy engine should never be consulted for a blocked identity")
	return policydomain.Decision{}
}

func TestHandler_BlockedIdentity_RejectedBeforePolicyEvaluation(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	const blockReason = "anomalous tool-call pattern detected"

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(panickingEngine{t: t})
	autoBlock := fakeAutoBlockChecker{verdict: anomalydomain.BlockVerdict{Allowed: false, Reason: blockReason, RetryAfter: 90 * time.Second}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, autoBlock)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream should not have been called for a blocked identity")
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "blocked" {
		t.Fatalf("expected one blocked audit entry, got %+v", writer.entries)
	}
	if writer.entries[0].Reason != blockReason {
		t.Errorf("expected the audit log to capture the detailed reason %q, got %q", blockReason, writer.entries[0].Reason)
	}
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected a Retry-After header on a 403 blocked response")
	}
	if seconds, err := strconv.Atoi(retryAfter); err != nil || seconds != 90 {
		t.Errorf("expected Retry-After of 90 seconds, got %q", retryAfter)
	}
	env := decodeJSONRPCError(t, w)
	if env.Error.Message != "blocked due to anomalous behavior" {
		t.Errorf("expected a generic blocked message, got %q", env.Error.Message)
	}
	if strings.Contains(env.Error.Message, blockReason) {
		t.Error("response body must never contain the detailed anomaly-detection reason")
	}
}

func TestHandler_AutoBlockCheckerNil_BehavesIdenticallyToBefore(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
}
