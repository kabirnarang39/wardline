package adapter

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	approvalusecase "github.com/kabirnarang39/wardline/internal/features/approval/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	auditusecase "github.com/kabirnarang39/wardline/internal/features/audit/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	prdomain "github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// BudgetChecker is the subset of budgetusecase.Checker's behavior Handler
// depends on — a narrow interface so tests can supply a fake without
// importing the real usecase package's flags/limiter wiring.
type BudgetChecker interface {
	Check(identity, tenant, tool string, now time.Time) budgetdomain.Verdict
}

// AutoBlockChecker is the subset of anomaly/usecase.BlockChecker's
// behavior Handler depends on -- mirrors BudgetChecker's exact shape
// (identity, tenant), with tenantName threaded through so a block is
// scoped to (tenant, identity), not identity alone (two tenants can
// plausibly provision an identically-named identity via SCIM).
type AutoBlockChecker interface {
	Check(identity, tenantName string, now time.Time) anomalydomain.BlockVerdict
}

// ApprovalPort drives the needs_approval outcome: it admits a call that
// already holds an operator grant, otherwise enqueues a pending request.
// Nil when the approval_workflow feature isn't wired — the handler fails
// closed (denies) on needs_approval in that case. Satisfied by
// approvalusecase.Manager.
type ApprovalPort interface {
	OnNeedsApproval(tenant, identity, tool, method, session string, params map[string]string) (approvalusecase.Result, error)
}

// JSON-RPC error codes. This isn't a full JSON-RPC error code
// taxonomy — just enough to distinguish "we couldn't understand the
// request" from "we understood it and something downstream went wrong".
const (
	rpcCodeParseError   = -32700 // malformed/oversized/unparsable request body
	rpcCodeUnauthorized = -32001 // identity authentication failure
	rpcCodeServerErr    = -32000 // policy deny, budget throttling, or upstream failure (reserved server-error range)
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
	decider          *proxyusecase.Decider
	recorder         *auditusecase.Recorder
	upstream         *httputil.ReverseProxy
	budgetChecker    BudgetChecker
	autoBlockChecker AutoBlockChecker
	identityAuth     IdentityAuthenticator
	tracer           trace.Tracer
	logger           *slog.Logger
	now              func() time.Time
	// trustedIdentityHeader names the header credential/adapter.Handler
	// trusts to carry an already-verified SPIFFE ID under
	// bootstrap_source: mtls. Non-empty only in that mode; stripped
	// before forwarding for exactly the reason Authorization is (see
	// forward()).
	trustedIdentityHeader string

	// approval is nil unless the approval_workflow feature is wired; a nil
	// port makes needs_approval fail closed (deny) — see ServeHTTP.
	approval ApprovalPort

	// sessionHeader names the request header carrying an explicit agent
	// session id, plumbed onto ToolCall.SessionID and the audit Entry so
	// taint/approval scope to a session, not just (tenant, identity). "" (the
	// default NewHandler passes) disables it — r.Header.Get("") returns "".
	sessionHeader string
}

// autoBlockChecker is nil-able: the anomaly-detection feature it backs is
// gated by a feature flag (see CLAUDE.md "Feature flags"), and callers that
// don't wire one up (including every existing test in this package) get the
// pre-anomaly-detection behavior unchanged via the nil check in ServeHTTP.
// trustedIdentityHeader is "" for every bootstrap source but mtls.
func NewHandler(decider *proxyusecase.Decider, recorder *auditusecase.Recorder, upstream *url.URL, budgetChecker BudgetChecker, tracer trace.Tracer, identityAuth IdentityAuthenticator, logger *slog.Logger, autoBlockChecker AutoBlockChecker, trustedIdentityHeader string) *Handler {
	return NewHandlerWithApproval(decider, recorder, upstream, budgetChecker, tracer, identityAuth, logger, autoBlockChecker, trustedIdentityHeader, nil, "")
}

// NewHandlerWithApproval is NewHandler plus an ApprovalPort (wired only when
// the approval_workflow feature is on — a nil port, what NewHandler passes,
// makes a needs_approval policy outcome fail closed) and a session header
// (plumbed whenever taint or approval is on; "" disables it).
func NewHandlerWithApproval(decider *proxyusecase.Decider, recorder *auditusecase.Recorder, upstream *url.URL, budgetChecker BudgetChecker, tracer trace.Tracer, identityAuth IdentityAuthenticator, logger *slog.Logger, autoBlockChecker AutoBlockChecker, trustedIdentityHeader string, approval ApprovalPort, sessionHeader string) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// Clone http.DefaultTransport rather than starting from a zero-value
	// &http.Transport{} so we keep its dial/TLS-handshake timeouts, HTTP/2
	// support, connection pooling, and Proxy: ProxyFromEnvironment — only
	// ResponseHeaderTimeout is overridden.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = upstreamResponseHeaderTimeout
	proxy.Transport = tr
	return &Handler{
		decider:          decider,
		recorder:         recorder,
		upstream:         proxy,
		budgetChecker:    budgetChecker,
		autoBlockChecker: autoBlockChecker,
		identityAuth:     identityAuth,
		tracer:           tracer,
		logger:           logger,
		now:              time.Now,

		trustedIdentityHeader: trustedIdentityHeader,
		approval:              approval,
		sessionHeader:         sessionHeader,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()

	// Authentication happens before anything else — a rejected caller
	// never reaches policy, budget, or the audit log (see
	// docs/superpowers/specs/2026-07-27-credential-issuance-design.md
	// "Error handling"). HeaderIdentity (the default) never errors, so
	// this is a no-op when credential_issuance is off. The resolved
	// tenant flows into ParseRequest below, and from there into the
	// ToolCall/policy Context the Decider evaluates.
	identity, tenant, err := h.identityAuth.Authenticate(r)
	if err != nil {
		h.logger.Warn("identity authentication failed", "remote_addr", r.RemoteAddr)
		writeJSONRPCError(w, http.StatusUnauthorized, rpcCodeUnauthorized, nil, "unauthorized")
		return
	}

	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := h.tracer.Start(ctx, "wardline.proxy_request", trace.WithAttributes(attribute.String("wardline.identity", identity), attribute.String("wardline.tenant", tenant)))
	defer span.End()
	r = r.WithContext(ctx)

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.finish(span, identity, tenant, "", "error", "", "", start, nil, "")
		writeJSONRPCError(w, http.StatusBadRequest, rpcCodeParseError, nil, "cannot read body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	parsed, err := proxyusecase.ParseRequest(identity, tenant, body)
	if err != nil {
		h.finish(span, identity, tenant, "", "error", "", "", start, nil, "")
		writeJSONRPCError(w, http.StatusBadRequest, rpcCodeParseError, parsed.ID, err.Error())
		return
	}

	// The auto-block gate runs before policy evaluation (and before the
	// passthrough/tool-call split below) so a blocked identity's call never
	// reaches the policy engine — call.Tool isn't parsed yet at this point,
	// so "" is used for tool, matching the parse-error paths above.
	if h.autoBlockChecker != nil {
		blockVerdict := h.autoBlockChecker.Check(identity, tenant, start)
		if !blockVerdict.Allowed {
			h.finish(span, identity, tenant, "", "blocked", blockVerdict.Reason, parsed.Call.SessionID, start, nil, "")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(blockVerdict.RetryAfter)))
			writeJSONRPCError(w, http.StatusForbidden, rpcCodeServerErr, parsed.ID, "blocked due to anomalous behavior")
			return
		}
	}

	if !parsed.IsGated {
		// True protocol-lifecycle/discovery MCP methods (initialize,
		// notifications/initialized, tools/list, etc.) are forwarded to
		// upstream without policy or budget evaluation — every real MCP
		// client performs this handshake before its first tool call. See
		// docs/superpowers/specs/2026-07-27-mcp-protocol-passthrough-design.md.
		h.forward(w, r, span, parsed, identity, tenant, parsed.Method, parsed.ID, start, "passthrough", "")
		return
	}

	call := parsed.Call
	call.Timestamp = start
	call.RemoteAddr = r.RemoteAddr
	call.UserAgent = r.Header.Get("User-Agent")
	// Populate the session id from the configured header (r.Header.Get("")
	// returns "" when the feature is disabled). Set on parsed.Call too so the
	// approval port and every parsed-in-scope finish/forward call — which read
	// parsed.Call.SessionID — carry the same value.
	call.SessionID = r.Header.Get(h.sessionHeader)
	parsed.Call.SessionID = call.SessionID

	// auditTool is what's recorded/traced for this request. call.Tool is
	// "" only for an untargeted resources/prompts call (e.g.
	// resources/list) -- falling back to the method name there keeps the
	// audit trail from ever recording a blank Tool for a policy-evaluated
	// entry, without changing what a policy rule actually matches against
	// (that's still call.Tool == "", unaffected by this fallback).
	auditTool := call.Tool
	if auditTool == "" {
		auditTool = call.Method
	}

	verdict := h.decider.Decide(call)
	switch verdict.Outcome {
	case prdomain.OutcomeNeedsApproval:
		if h.approval == nil {
			// Fail closed: policy asked for approval but the feature isn't
			// wired, so there's no way to obtain one — deny.
			h.finish(span, identity, tenant, auditTool, "deny", verdict.Reason, parsed.Call.SessionID, start, nil, "")
			writeJSONRPCError(w, http.StatusForbidden, rpcCodeServerErr, parsed.ID, "denied by policy")
			return
		}
		redacted := proxyusecase.RedactSecrets(proxyusecase.ShallowParams(parsed.Call.Params))
		res, err := h.approval.OnNeedsApproval(tenant, identity, auditTool, parsed.Method, parsed.Call.SessionID, redacted)
		if err != nil {
			h.finish(span, identity, tenant, auditTool, "deny", err.Error(), parsed.Call.SessionID, start, nil, "")
			writeJSONRPCError(w, http.StatusForbidden, rpcCodeServerErr, parsed.ID, "denied by policy")
			return
		}
		if !res.Approved {
			h.finish(span, identity, tenant, auditTool, "needs_approval", verdict.Reason, parsed.Call.SessionID, start, nil, "")
			writeJSONRPCError(w, http.StatusAccepted, rpcCodeServerErr, parsed.ID, "awaiting operator approval; retry after approval (pending id: "+res.PendingID+")")
			return
		}
		// res.Approved: a live grant admits this call — fall through to the
		// allow/forward path below.
	case prdomain.OutcomeDeny:
		// verdict.Reason may carry detailed policy-engine diagnostics (with
		// the OPA backend, potentially internal error text, file paths, or
		// rule names) — record it in the audit log for the operator, but
		// never echo it to the untrusted HTTP caller.
		h.finish(span, identity, tenant, auditTool, "deny", verdict.Reason, parsed.Call.SessionID, start, nil, "")
		writeJSONRPCError(w, http.StatusForbidden, rpcCodeServerErr, parsed.ID, "denied by policy")
		return
	}

	if !parsed.IsToolCall {
		// resources/* and prompts/* calls are policy-evaluated but not
		// budget-checked -- budget buckets are keyed by tool name, and
		// widening that key space to arbitrary resource URIs is a
		// separate design question, deliberately out of scope. See
		// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
		h.forward(w, r, span, parsed, identity, tenant, auditTool, parsed.ID, start, "allow", "")
		return
	}

	budgetVerdict := h.budgetChecker.Check(identity, tenant, call.Tool, start)
	if !budgetVerdict.Allowed {
		// Same reasoning as the policy-deny path above: detailed reason to
		// the audit log, generic message to the caller.
		h.finish(span, identity, tenant, auditTool, "throttled", budgetVerdict.Reason, parsed.Call.SessionID, start, nil, "")
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(budgetVerdict.RetryAfter)))
		writeJSONRPCError(w, http.StatusTooManyRequests, rpcCodeServerErr, parsed.ID, "throttled by budget")
		return
	}

	// A fail-open verdict is an allow that skipped enforcement entirely.
	// Carry its reason into the audit entry so the skip leaves a durable
	// trace — the Warn log line the limiter emits is one line per request,
	// easy to lose under load, and /readyz stays green through the
	// query-level failures that trigger this. An ordinary allow keeps its
	// empty reason: only a genuine fail-open populates this.
	successReason := ""
	if budgetVerdict.FailedOpen {
		successReason = budgetVerdict.Reason
	}

	h.forward(w, r, span, parsed, identity, tenant, auditTool, parsed.ID, start, "allow", successReason)
}

// forward proxies the request upstream, recording exactly one audit entry
// depending on whether the upstream call succeeded or failed. successDecision
// is the decision recorded on a successful upstream response — "allow" for a
// policy-evaluated tool call, "passthrough" for a protocol-lifecycle method
// that skipped policy/budget evaluation entirely. successReason is the
// reason recorded alongside it — empty for an ordinary allow (and always
// empty for passthrough, which never reaches a budget check), non-empty
// only when the budget check failed open and that needs a durable trace.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, span trace.Span, parsed prdomain.ParsedRequest, identity, tenant, tool string, id json.RawMessage, start time.Time, successDecision, successReason string) {
	proxy := *h.upstream // shallow copy: per-request ErrorHandler/ModifyResponse closures
	recorded := false
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		recorded = true
		// The upstream never responded, so a claimed write definitely did not
		// take effect — record it as contradicted.
		eff, st := proxyusecase.ExtractEffect(parsed, proxyusecase.EffectSignal{ResponseStatus: http.StatusBadGateway}, proxyusecase.RedactSecrets)
		h.finish(span, identity, tenant, tool, "error", "", parsed.Call.SessionID, start, eff, st)
		writeJSONRPCError(w, http.StatusBadGateway, rpcCodeServerErr, id, "upstream unreachable")
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !recorded {
			recorded = true
			sig := readResponseSignal(resp)
			eff, st := proxyusecase.ExtractEffect(parsed, sig, proxyusecase.RedactSecrets)
			h.finish(span, identity, tenant, tool, successDecision, successReason, parsed.Call.SessionID, start, eff, st)
		}
		return nil
	}
	// httputil.ReverseProxy does not strip Authorization (it's not a
	// hop-by-hop header) — without this, the bearer credential the caller
	// authenticated to Wardline with would be forwarded verbatim to the
	// untrusted upstream MCP server, handing it a live, replayable Wardline
	// credential. Safe unconditionally: Wardline injects no upstream
	// credential of its own today, so nothing downstream depends on this
	// header surviving.
	r.Header.Del("Authorization")

	// mtls bootstrap mode trusts this header the same way Authorization
	// is trusted above -- same rationale, same fix: never let it reach
	// the untrusted upstream, which would otherwise learn the exact
	// string it needs to mint its own Wardline bearer tokens.
	if h.trustedIdentityHeader != "" {
		r.Header.Del(h.trustedIdentityHeader)
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
func (h *Handler) finish(span trace.Span, identity, tenant, tool, decision, reason, sessionID string, start time.Time, effect *auditdomain.Effect, status auditdomain.EffectStatus) {
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
	// ponytail: explicit success allowlist, not a switch with a default —
	// decision is a closed set of 7 literals this file alone produces
	// ("allow", "deny", "throttled", "passthrough", "error", "blocked",
	// "needs_approval"), not caller-controlled. A future 8th decision value needs a human to add
	// it here too; forgetting fails safe (Error), not silently open.
	// Upgrade to a typed decision enum with an exhaustive switch if that
	// becomes a real maintenance pain point.
	if decision != "allow" && decision != "passthrough" {
		span.SetStatus(codes.Error, reason)
	}
	var traceID string
	if sc := span.SpanContext(); sc.IsValid() {
		traceID = sc.TraceID().String()
	}
	h.record(identity, tenant, tool, decision, reason, traceID, sessionID, start, effect, status)
}

func (h *Handler) record(identity, tenant, tool, decision, reason, traceID, sessionID string, start time.Time, effect *auditdomain.Effect, status auditdomain.EffectStatus) {
	h.recorder.RecordWithEffect(identity, tenant, tool, decision, reason, traceID, h.now().Sub(start), start, sessionID, effect, status)
}

// readResponseSignal reads a bounded prefix of the upstream response body to
// detect a JSON-RPC error or an MCP no-op, then restores the body so the proxy
// streams it to the client unchanged. Only the prefix is inspected — a no-op
// signal past the cap is missed (conservative: defaults to unconfirmed, never a
// false contradiction).
func readResponseSignal(resp *http.Response) proxyusecase.EffectSignal {
	sig := proxyusecase.EffectSignal{ResponseStatus: resp.StatusCode}
	if resp.Body == nil {
		return sig
	}
	const cap = 8 << 10 // 8 KiB
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, cap))
	if err != nil {
		return sig
	}
	rest := resp.Body
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), rest), rest}

	var env struct {
		Error  json.RawMessage `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(prefix, &env) != nil {
		return sig
	}
	if len(env.Error) > 0 && string(env.Error) != "null" {
		sig.RPCError = true
	}
	sig.NoOpSignal = resultIsNoOp(env.Result)
	return sig
}

// resultIsNoOp reports whether a JSON-RPC result signals that nothing
// happened: absent/null/empty result, MCP's result.isError == true, or a
// shallow success:false.
func resultIsNoOp(result json.RawMessage) bool {
	s := strings.TrimSpace(string(result))
	if s == "" || s == "null" || s == "{}" || s == "[]" {
		return true
	}
	var obj struct {
		IsError *bool `json:"isError"`
		Success *bool `json:"success"`
	}
	if json.Unmarshal(result, &obj) == nil {
		if obj.IsError != nil && *obj.IsError {
			return true
		}
		if obj.Success != nil && !*obj.Success {
			return true
		}
	}
	return false
}
