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
	approvalusecase "github.com/kabirnarang39/wardline/internal/features/approval/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	jobbudgetdomain "github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	policyusecase "github.com/kabirnarang39/wardline/internal/features/policy/usecase"
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

func (alwaysAllowBudgetChecker) Check(identity, tenant, tool string, now time.Time) budgetdomain.Verdict {
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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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

// TestHandler_TrustedIdentityHeaderStrippedBeforeForwarding proves the
// mtls-bootstrap-mode trusted identity header is stripped before
// forwarding to the untrusted upstream MCP server -- same rationale, same
// fix as TestHandler_AuthorizationHeaderStrippedBeforeForwarding above: an
// untrusted upstream must never learn the exact string it needs to mint
// its own valid Wardline bearer tokens.
func TestHandler_TrustedIdentityHeaderStrippedBeforeForwarding(t *testing.T) {
	const trustedHeader = "X-Wardline-Verified-Spiffe-Id"

	var gotTrustedHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTrustedHeader = r.Header.Get(trustedHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, trustedHeader)

	req := newRequest("agent-abc123", "read_file")
	req.Header.Set(trustedHeader, "spiffe://example.org/ns/prod/sa/payments-worker")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotTrustedHeader != "" {
		t.Errorf("expected the upstream to never see the trusted identity header, got %q", gotTrustedHeader)
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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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

func (f fakeBudgetChecker) Check(identity, tenant, tool string, now time.Time) budgetdomain.Verdict {
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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, tracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, tracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, budgetChecker, tracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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

func (c *countingBudgetChecker) Check(identity, tenant, tool string, now time.Time) budgetdomain.Verdict {
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
	h := adapter.NewHandler(decider, recorder, upstreamURL, budget, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	h := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, tracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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

// TestHandler_GatedResourcesReadAllowed_SkipsBudgetButRunsPolicy is the
// widening feature's core handler-level proof: a resources/read request
// IS evaluated by the policy engine (unlike passthrough), but the budget
// checker is never consulted even on allow — see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
func TestHandler_GatedResourcesReadAllowed_SkipsBudgetButRunsPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	engine := &countingEngine{fakeEngine: fakeEngine{effect: policydomain.EffectAllow}}
	budget := &countingBudgetChecker{}
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(engine)
	h := adapter.NewHandler(decider, recorder, upstreamURL, budget, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///data/report.csv"}}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Wardline-Identity", "agent-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if engine.calls != 1 {
		t.Errorf("expected policy engine to be consulted exactly once for a gated resources/read, got %d calls", engine.calls)
	}
	if budget.calls != 0 {
		t.Errorf("expected budget checker to never be consulted for a resources/read, got %d calls", budget.calls)
	}
	if len(writer.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(writer.entries))
	}
	entry := writer.entries[0]
	if entry.Decision != "allow" {
		t.Errorf("expected decision %q, got %q", "allow", entry.Decision)
	}
	if entry.Tool != "file:///data/report.csv" {
		t.Errorf("expected Tool to hold the resource uri, got %q", entry.Tool)
	}
}

// TestHandler_GatedResourcesReadDenied_NeverReachesUpstreamOrBudget
// proves a policy deny on a gated resources/prompts request behaves
// exactly like a tools/call deny: 403, never forwarded, budget never
// consulted.
func TestHandler_GatedResourcesReadDenied_NeverReachesUpstreamOrBudget(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	engine := &countingEngine{fakeEngine: fakeEngine{effect: policydomain.EffectDeny}}
	budget := &countingBudgetChecker{}
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(engine)
	h := adapter.NewHandler(decider, recorder, upstreamURL, budget, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"summarize"}}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Wardline-Identity", "agent-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if upstreamHit {
		t.Error("expected upstream to never be reached for a denied resources/prompts call")
	}
	if budget.calls != 0 {
		t.Errorf("expected budget checker to never be consulted for a denied resources/prompts call, got %d calls", budget.calls)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "deny" {
		t.Fatalf("expected one deny audit entry, got %+v", writer.entries)
	}
	if writer.entries[0].Tool != "summarize" {
		t.Errorf("expected Tool to hold the prompt name, got %q", writer.entries[0].Tool)
	}
}

// TestHandler_GatedListCall_AuditFallsBackToMethodName proves an
// untargeted resources/prompts call (list-style, no uri/name) records
// the method name as the audit Tool instead of a blank string, while the
// policy Context it was evaluated against still saw an empty Tool (that
// distinction matters for what a rule can match — see matcher_test.go's
// TestMatcher_UntargetedListCallOnlyMatchesWildcardOrDefault).
func TestHandler_GatedListCall_AuditFallsBackToMethodName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	engine := &contextRecordingEngine{}
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(engine)
	h := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Wardline-Identity", "agent-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if engine.received.Tool != "" {
		t.Errorf("expected policy Context.Tool to stay empty for an untargeted list call, got %q", engine.received.Tool)
	}
	if engine.received.Method != "resources/list" {
		t.Errorf("expected policy Context.Method %q, got %q", "resources/list", engine.received.Method)
	}
	if len(writer.entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(writer.entries))
	}
	if writer.entries[0].Tool != "resources/list" {
		t.Errorf("expected audit Tool to fall back to the method name, got %q", writer.entries[0].Tool)
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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, failingIdentityAuth{}, testLogger, nil, "")

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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.NewBearerIdentity(fakeSucceedingAuthenticator{identity: "agent-abc123"}), testLogger, nil, "")

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

func (f fakeAutoBlockChecker) Check(identity, tenantName string, now time.Time) anomalydomain.BlockVerdict {
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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, autoBlock, "")

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

// newTenantScopedRequest is like newRequest but also sets the
// X-Wardline-Tenant header, so HeaderIdentity resolves a real (non-default)
// tenant for the request.
func newTenantScopedRequest(identity, tenant, tool string) *http.Request {
	req := newRequest(identity, tool)
	req.Header.Set("X-Wardline-Tenant", tenant)
	return req
}

// TestHandler_TenantScopedPolicyRuleGatesRealProxiedCall proves tenant
// actually gates a real proxied tool call end-to-end through Handler.ServeHTTP
// — not just at the Matcher/Decider unit level. It wires the real
// policyusecase.Matcher (the production YAML-rule engine, not a test fake)
// with a rule scoped to tenant "acme", and sends the exact same
// identity+tool through two requests that differ only in their resolved
// tenant (via the real HeaderIdentity authenticator reading
// X-Wardline-Tenant): "acme" must be allowed through to upstream, any other
// tenant must be denied before upstream is ever reached. This is the moment
// tenant becomes real for the hot proxy path, not just plumbing.
func TestHandler_TenantScopedPolicyRuleGatesRealProxiedCall(t *testing.T) {
	rules := []policydomain.Rule{
		{Identity: "agent-abc123", Tool: "read_file", Effect: policydomain.EffectAllow, Tenant: "acme"},
	}
	matcher := policyusecase.NewMatcher(rules, policydomain.EffectDeny)
	decider := proxyusecase.NewDecider(matcher)

	newHandler := func(t *testing.T, upstreamHit *bool) *adapter.Handler {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*upstreamHit = true
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstream.Close)
		upstreamURL, _ := url.Parse(upstream.URL)
		writer := &fakeWriter{}
		recorder := auditusecase.NewRecorder(writer, nil, nil)
		return adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")
	}

	t.Run("matching tenant reaches upstream", func(t *testing.T) {
		var upstreamHit bool
		handler := newHandler(t, &upstreamHit)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newTenantScopedRequest("agent-abc123", "acme", "read_file"))

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for tenant acme, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !upstreamHit {
			t.Error("expected upstream to be reached for the allowed tenant")
		}
	})

	t.Run("mismatched tenant denied before upstream", func(t *testing.T) {
		var upstreamHit bool
		handler := newHandler(t, &upstreamHit)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newTenantScopedRequest("agent-abc123", "other-tenant", "read_file"))

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for a mismatched tenant, got %d (body: %s)", w.Code, w.Body.String())
		}
		if upstreamHit {
			t.Error("upstream should never be reached for a tenant that doesn't match the policy rule")
		}
	})
}

// TestHandler_RecordsResolvedTenantOnAuditEntry proves the tenant resolved
// by IdentityAuthenticator flows all the way through to the recorded audit
// Entry — the point of threading tenantName through Handler.finish/record
// into Recorder.Record.
func TestHandler_RecordsResolvedTenantOnAuditEntry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newTenantScopedRequest("agent-abc123", "acme", "read_file"))

	if len(writer.entries) != 1 || writer.entries[0].Tenant != "acme" {
		t.Fatalf("expected audit entry Tenant %q, got %+v", "acme", writer.entries)
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
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
}

// stubBudgetChecker returns a fixed verdict, so a test can drive the
// handler down the fail-open branch without a real Postgres backend.
type stubBudgetChecker struct {
	verdict budgetdomain.Verdict
}

func (s stubBudgetChecker) Check(identity, tenant, tool string, now time.Time) budgetdomain.Verdict {
	return s.verdict
}

// TestHandler_FailOpenBudgetVerdictRecordsReasonInAudit proves a budget
// check that failed open leaves a durable trace in the audit log rather
// than being indistinguishable from an ordinary allow. The Warn log the
// limiter emits is one line per request (easy to lose under load) and
// /readyz stays green through the query-level failures that cause this,
// so the audit entry is the only durable signal that enforcement was
// skipped for this call.
func TestHandler_FailOpenBudgetVerdictRecordsReasonInAudit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	const failOpenReason = "budget check failed open: dial tcp: connection refused"

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	checker := stubBudgetChecker{verdict: budgetdomain.Verdict{Allowed: true, FailedOpen: true, Reason: failOpenReason}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, checker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail open means the call proceeds), got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
	if writer.entries[0].Reason != failOpenReason {
		t.Errorf("expected the fail-open reason %q recorded in the audit entry, got %q", failOpenReason, writer.entries[0].Reason)
	}
}

// TestHandler_OrdinaryAllowRecordsEmptyAuditReason is the regression guard
// on the other side of the fail-open threading: an ordinary allow must keep
// recording an empty reason. Without this, threading the verdict's reason
// through unconditionally would stamp "within budget" (or whatever the
// limiter happens to say) onto every single successful call's audit entry.
func TestHandler_OrdinaryAllowRecordsEmptyAuditReason(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	checker := stubBudgetChecker{verdict: budgetdomain.Verdict{Allowed: true, Reason: "within budget"}}
	handler := adapter.NewHandler(decider, recorder, upstreamURL, checker, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow audit entry, got %+v", writer.entries)
	}
	if writer.entries[0].Reason != "" {
		t.Errorf("expected an ordinary allow to record an empty audit reason, got %q", writer.entries[0].Reason)
	}
}

// TestHandler_UpstreamRPCErrorRecordsContradictedEffect proves the proxy
// captures the proxy-visible response signal: a write-shaped tools/call whose
// upstream returns a JSON-RPC error body is recorded as a contradicted effect
// (the claimed write demonstrably did not take effect), with a non-nil Effect
// carrying the claimed op. Observe-only — the client still gets the upstream
// body unchanged and the decision stays "allow".
func TestHandler_UpstreamRPCErrorRecordsContradictedEffect(t *testing.T) {
	const upstreamBody = `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"permission denied"}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (proxy passes the upstream status through), got %d", w.Code)
	}
	if got := w.Body.String(); got != upstreamBody {
		t.Errorf("expected the client to receive the upstream body unchanged, got %q", got)
	}
	if len(writer.entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(writer.entries))
	}
	e := writer.entries[0]
	if e.Decision != "allow" {
		t.Errorf("effect capture must not change the decision; got %q", e.Decision)
	}
	if e.EffectStatus != auditdomain.EffectStatusContradicted {
		t.Errorf("expected a contradicted effect from a JSON-RPC error body, got %q", e.EffectStatus)
	}
	if e.Effect == nil {
		t.Fatal("expected a non-nil Effect for a write-shaped call")
	}
	if e.Effect.ClaimedOp != "tools/call" {
		t.Errorf("expected ClaimedOp tools/call, got %q", e.Effect.ClaimedOp)
	}
	if !e.Effect.RPCError {
		t.Error("expected the captured Effect to flag the JSON-RPC error")
	}
}

type fakeApproval struct {
	approved  bool
	pendingID string
}

func (f fakeApproval) OnNeedsApproval(_, _, _, _, _ string, _ map[string]string) (approvalusecase.Result, error) {
	return approvalusecase.Result{Approved: f.approved, PendingID: f.pendingID}, nil
}

func TestHandler_NeedsApprovalEnqueuesReturns202(t *testing.T) {
	// upstream should NOT be hit
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamHit = true }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectNeedsApproval})
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "", fakeApproval{approved: false, pendingID: "pid-1"}, "", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream must not be hit for a pending approval")
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "needs_approval" {
		t.Fatalf("expected one needs_approval entry, got %+v", writer.entries)
	}
}

func TestHandler_NeedsApprovalWithGrantForwards(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"result":"ok"}`)) }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectNeedsApproval})
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "", fakeApproval{approved: true}, "", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a granted retry, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow entry, got %+v", writer.entries)
	}
	// A grant-consumed allow must carry a distinguishing reason so its audit
	// entry doesn't read identically to an ordinary, never-gated allow.
	if reason := writer.entries[0].Reason; reason == "" {
		t.Fatal("expected a non-empty Reason marking this allow as approved via grant")
	}
}

func TestHandler_NeedsApprovalNilPortFailsClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectNeedsApproval})
	// existing constructor: no approval port wired
	handler := adapter.NewHandler(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "delete_file"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (fail closed) when approval unwired, got %d", w.Code)
	}
}

// TestHandler_SessionHeaderRecordedOnEntry proves the configured session
// header is read off the request and threaded into the recorded audit Entry
// — the taint/approval scope key the rest of the pipeline reads.
func TestHandler_SessionHeaderRecordedOnEntry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "", nil, "X-Wardline-Session", nil)

	req := newRequest("agent-abc123", "delete_file")
	req.Header.Set("X-Wardline-Session", "run-7")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].SessionID != "run-7" {
		t.Fatalf("expected one entry with SessionID=run-7, got %+v", writer.entries)
	}
}

// TestHandler_SessionHeaderRecordedOnBlockedEntry proves the session id is
// populated before the auto-block gate, so a "blocked" audit Entry carries it
// too — the block path records parsed.Call.SessionID before the gated-call
// branch runs.
func TestHandler_SessionHeaderRecordedOnBlockedEntry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(panickingEngine{t: t})
	autoBlock := fakeAutoBlockChecker{verdict: anomalydomain.BlockVerdict{Allowed: false, Reason: "blocked"}}
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, autoBlock, "", nil, "X-Wardline-Session", nil)

	req := newRequest("agent-abc123", "delete_file")
	req.Header.Set("X-Wardline-Session", "run-9")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "blocked" || writer.entries[0].SessionID != "run-9" {
		t.Fatalf("expected one blocked entry with SessionID=run-9, got %+v", writer.entries)
	}
}

// stubJobBudgetChecker is a fixed-verdict JobBudgetChecker for tests --
// mirrors alwaysAllowBudgetChecker's role for the per-window BudgetChecker.
type stubJobBudgetChecker struct{ verdict jobbudgetdomain.Verdict }

func (s stubJobBudgetChecker) Check(_, _, _ string, _ time.Time) jobbudgetdomain.Verdict {
	return s.verdict
}

// TestHandler_JobBudgetExceededReturns429WithDistinctDecision proves the
// per-job ceiling hard gate returns 429 with its own "job_budget_exceeded"
// audit decision -- distinct from the per-window budget's "throttled" -- and
// never reaches upstream.
func TestHandler_JobBudgetExceededReturns429WithDistinctDecision(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamHit = true }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	jb := stubJobBudgetChecker{verdict: jobbudgetdomain.Verdict{Allowed: false, Reason: "job budget ceiling 500 reached", Count: 501}}
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "", nil, "", jb)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if upstreamHit {
		t.Fatal("upstream must not be hit once the job budget ceiling is exceeded")
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "job_budget_exceeded" {
		t.Fatalf("expected one job_budget_exceeded entry (distinct from throttled), got %+v", writer.entries)
	}
}

// TestHandler_JobBudgetUnderCeilingForwards proves an allowed job-budget
// verdict does not block the call from reaching upstream.
func TestHandler_JobBudgetUnderCeilingForwards(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"result":"ok"}`)) }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	jb := stubJobBudgetChecker{verdict: jobbudgetdomain.Verdict{Allowed: true, Count: 3}}
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "", nil, "", jb)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(writer.entries) != 1 || writer.entries[0].Decision != "allow" {
		t.Fatalf("expected one allow entry, got %+v", writer.entries)
	}
}

// TestHandler_JobBudgetNilCheckerNoEffect proves a nil JobBudgetChecker
// (feature off) leaves behavior unchanged -- the established pattern for
// every optional port on this Handler.
func TestHandler_JobBudgetNilCheckerNoEffect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"result":"ok"}`)) }))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	writer := &fakeWriter{}
	recorder := auditusecase.NewRecorder(writer, nil, nil)
	decider := proxyusecase.NewDecider(fakeEngine{effect: policydomain.EffectAllow})
	handler := adapter.NewHandlerWithApproval(decider, recorder, upstreamURL, alwaysAllowBudgetChecker{}, noopTracer, adapter.HeaderIdentity{}, testLogger, nil, "", nil, "", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest("agent-abc123", "read_file"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with job budget unwired (feature off), got %d", w.Code)
	}
}
