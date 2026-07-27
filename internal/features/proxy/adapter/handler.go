package adapter

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// BudgetChecker is the subset of budgetusecase.Checker's behavior Handler
// depends on — a narrow interface so tests can supply a fake without
// importing the real usecase package's flags/limiter wiring.
type BudgetChecker interface {
	Check(identity string, now time.Time) budgetdomain.Verdict
}

// JSON-RPC error codes used for v0.1. This isn't a full JSON-RPC error code
// taxonomy — just enough to distinguish "we couldn't understand the
// request" from "we understood it and something downstream went wrong".
const (
	rpcCodeParseError = -32700 // malformed/oversized/unparsable request body
	rpcCodeServerErr  = -32000 // policy deny, budget throttling, or upstream failure (reserved server-error range)
)

type jsonRPCErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCErrorResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      json.RawMessage  `json:"id"`
	Error   jsonRPCErrorBody `json:"error"`
}

// writeJSONRPCError writes a valid, labeled JSON-RPC 2.0 error envelope
// instead of a plain-text body, so callers get a parseable error shape
// consistent with the protocol they spoke to reach us.
func writeJSONRPCError(w http.ResponseWriter, status, code int, id json.RawMessage, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonRPCErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   jsonRPCErrorBody{Code: code, Message: message},
	})
}

// upstreamResponseHeaderTimeout bounds how long we wait for a connected
// upstream to start responding; MCP tool calls are fast, so 30s is generous.
const upstreamResponseHeaderTimeout = 30 * time.Second

// maxRequestBodyBytes caps how much of the request body we'll read before
// any policy check runs; MCP tool-call payloads are small JSON-RPC
// envelopes, so 1 MiB is generous headroom, not a real limit in practice.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// Handler is the HTTP entry point: parse each request, ask the Decider for
// a verdict, check the budget, record exactly one audit entry per request
// (with a trace ID for correlation), and forward allowed calls to the
// upstream MCP server.
type Handler struct {
	decider       *proxyusecase.Decider
	recorder      *auditusecase.Recorder
	upstream      *httputil.ReverseProxy
	budgetChecker BudgetChecker
	tracer        trace.Tracer
	now           func() time.Time
}

func NewHandler(decider *proxyusecase.Decider, recorder *auditusecase.Recorder, upstream *url.URL, budgetChecker BudgetChecker, tracer trace.Tracer) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// Clone http.DefaultTransport rather than starting from a zero-value
	// &http.Transport{} so we keep its dial/TLS-handshake timeouts, HTTP/2
	// support, connection pooling, and Proxy: ProxyFromEnvironment — only
	// ResponseHeaderTimeout is overridden.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = upstreamResponseHeaderTimeout
	proxy.Transport = tr
	return &Handler{
		decider:       decider,
		recorder:      recorder,
		upstream:      proxy,
		budgetChecker: budgetChecker,
		tracer:        tracer,
		now:           time.Now,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	identity := r.Header.Get("X-Wardline-Identity")

	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := h.tracer.Start(ctx, "wardline.proxy_request", trace.WithAttributes(attribute.String("wardline.identity", identity)))
	defer span.End()
	r = r.WithContext(ctx)

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.finish(span, identity, "", "error", "", start)
		writeJSONRPCError(w, http.StatusBadRequest, rpcCodeParseError, nil, "cannot read body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	parsed, err := proxyusecase.ParseRequest(identity, body)
	if err != nil {
		h.finish(span, identity, "", "error", "", start)
		writeJSONRPCError(w, http.StatusBadRequest, rpcCodeParseError, nil, err.Error())
		return
	}

	if !parsed.IsToolCall {
		// Non-tools/call MCP protocol methods (initialize,
		// notifications/initialized, tools/list, etc.) are forwarded to
		// upstream without policy or budget evaluation — Wardline's policy
		// model is scoped to tool calls, and every real MCP client performs
		// this handshake before its first tool call. See
		// docs/superpowers/specs/2026-07-27-mcp-protocol-passthrough-design.md.
		h.forward(w, r, span, identity, parsed.Method, parsed.ID, start, "passthrough")
		return
	}

	call := parsed.Call
	call.Timestamp = start
	call.RemoteAddr = r.RemoteAddr
	call.UserAgent = r.Header.Get("User-Agent")

	verdict := h.decider.Decide(call)
	if !verdict.Allow {
		// verdict.Reason may carry detailed policy-engine diagnostics (with
		// the OPA backend, potentially internal error text, file paths, or
		// rule names) — record it in the audit log for the operator, but
		// never echo it to the untrusted HTTP caller.
		h.finish(span, identity, call.Tool, "deny", verdict.Reason, start)
		writeJSONRPCError(w, http.StatusForbidden, rpcCodeServerErr, parsed.ID, "denied by policy")
		return
	}

	budgetVerdict := h.budgetChecker.Check(identity, start)
	if !budgetVerdict.Allowed {
		// Same reasoning as the policy-deny path above: detailed reason to
		// the audit log, generic message to the caller.
		h.finish(span, identity, call.Tool, "throttled", budgetVerdict.Reason, start)
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(budgetVerdict.RetryAfter)))
		writeJSONRPCError(w, http.StatusTooManyRequests, rpcCodeServerErr, parsed.ID, "throttled by budget")
		return
	}

	h.forward(w, r, span, identity, call.Tool, parsed.ID, start, "allow")
}

// forward proxies the request upstream, recording exactly one audit entry
// depending on whether the upstream call succeeded or failed. successDecision
// is the decision recorded on a successful upstream response — "allow" for a
// policy-evaluated tool call, "passthrough" for a protocol-lifecycle method
// that skipped policy/budget evaluation entirely.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, span trace.Span, identity, tool string, id json.RawMessage, start time.Time, successDecision string) {
	proxy := *h.upstream // shallow copy: per-request ErrorHandler/ModifyResponse closures
	recorded := false
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		recorded = true
		h.finish(span, identity, tool, "error", "", start)
		writeJSONRPCError(w, http.StatusBadGateway, rpcCodeServerErr, id, "upstream unreachable")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !recorded {
			recorded = true
			h.finish(span, identity, tool, successDecision, "", start)
		}
		return nil
	}
	// Inject Wardline's own span context into the outgoing request headers
	// before proxying, overwriting any traceparent the caller sent. Without
	// this, httputil.ReverseProxy copies the caller's original headers
	// verbatim, so an instrumented upstream would either see the caller's
	// trace context (making it a sibling of Wardline's span, not a child)
	// or nothing at all. This is a no-op when tracing is disabled (the
	// no-op propagator's Inject does nothing).
	otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
	proxy.ServeHTTP(w, r)
}

// retryAfterSeconds converts a budget verdict's RetryAfter into a whole
// number of seconds for the RFC 6585 Retry-After header, rounding up so we
// never tell a caller to retry before their window has actually reset (and
// never advertise 0 or negative seconds).
func retryAfterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		return 1
	}
	return s
}

// finish sets final span attributes/status and records exactly one audit
// entry for a completed request — every return point in
// ServeHTTP/forward needs both, so they're combined here rather than
// repeated at each call site.
func (h *Handler) finish(span trace.Span, identity, tool, decision, reason string, start time.Time) {
	span.SetAttributes(
		attribute.String("wardline.tool", tool),
		attribute.String("wardline.decision", decision),
	)
	// Explicit failure list rather than "everything but allow" — a
	// passthrough success (the MCP protocol handshake/discovery methods
	// every real client sends before its first tool call) is not a
	// failure and must not flip the span to Error.
	//
	// Note: reason may carry sensitive policy-engine diagnostics (see the
	// deny-path comment in ServeHTTP), and setting it as the span status
	// description means it leaves the process via the trace backend, which
	// typically has broader read access than the audit log this data is
	// otherwise carefully confined to. This is a deliberate, accepted
	// tradeoff, not an oversight — the operator opts into tracing and owns
	// their collector's access control.
	if decision == "deny" || decision == "throttled" || decision == "error" {
		span.SetStatus(codes.Error, reason)
	}
	var traceID string
	if sc := span.SpanContext(); sc.IsValid() {
		traceID = sc.TraceID().String()
	}
	h.record(identity, tool, decision, reason, traceID, start)
}

func (h *Handler) record(identity, tool, decision, reason, traceID string, start time.Time) {
	h.recorder.Record(identity, tool, decision, reason, traceID, h.now().Sub(start), start)
}
