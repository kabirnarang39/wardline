package domain

import (
	"encoding/json"
	"time"
)

// ToolCall is the parsed intent of an incoming MCP JSON-RPC request: which
// identity is trying to call which tool, with what arguments, when, and
// from where.
type ToolCall struct {
	Identity string

	// Tenant is the calling identity's tenant, resolved by
	// IdentityAuthenticator alongside Identity. "" means no tenant
	// scoping applies (see policydomain.Context.Tenant).
	Tenant string

	// Tool is the authoritative target identifier, extracted by Wardline's
	// own JSON parser: the tool name for a "tools/call", or (since the
	// resources/prompts widening) a resource URI for "resources/read" or
	// a prompt name for "prompts/get". "" for an untargeted
	// resources/prompts method (e.g. "resources/list") — see Method.
	// Downstream consumers (policy, audit) should always key off Tool,
	// never re-parse Params looking for a "name"/"uri" key.
	Tool string

	// Method is the JSON-RPC method this call arrived as ("tools/call",
	// "resources/read", "prompts/get", etc.), always populated for a
	// gated request (see domain.ParsedRequest.IsGated).
	Method string

	Params     json.RawMessage
	Timestamp  time.Time
	RemoteAddr string
	UserAgent  string

	// SessionID scopes an approval grant to a single agent session so a
	// grant issued for one session can't admit another's call. Populated
	// from the request by Task 9; "" until then (an unscoped grant).
	SessionID string
}

// Outcome is the three-way result of a policy evaluation: the call may
// proceed, is refused, or needs an operator's approval before it can.
type Outcome string

const (
	OutcomeAllow         Outcome = "allow"
	OutcomeDeny          Outcome = "deny"
	OutcomeNeedsApproval Outcome = "needs_approval"
)

// Verdict is the result of evaluating a ToolCall against policy. Allow is
// kept as a derived convenience (Outcome == OutcomeAllow) for existing
// callers that only distinguish proceed from not. The real pending-approval
// id (when Outcome is OutcomeNeedsApproval) flows through
// approval/usecase.Result.PendingID instead, read directly by the proxy
// handler -- Verdict has no field for it.
type Verdict struct {
	Allow   bool
	Outcome Outcome
	Reason  string

	// TaintSources names the untrusted-source tool(s) that tainted this
	// call's session, when taint_tracking is on and the session is
	// currently tainted -- nil otherwise (including when taint_tracking is
	// off, or the session was never tainted). Recorded regardless of
	// Outcome: an ALLOW under taint is exactly as worth an operator seeing
	// in the audit trail as a DENY under taint is, since policy (not this
	// field) is what decided whether taint mattered for this call.
	//
	// This closes a real gap: taint/domain.Label has carried this same
	// data (as Sources) since taint tracking shipped, but nothing ever
	// read it back out -- an operator investigating a tainted-write denial
	// could see THAT the call was tainted (via policy's own reason
	// string, if the policy author happened to say so) but never WHICH
	// untrusted call actually caused it, from Wardline's own audit trail.
	TaintSources []string
}

// TaintSignal is what a TaintLookup reports for one ToolCall: whether its
// session is currently tainted, and if so, which untrusted-source tool(s)
// caused it. A small, proxy-owned type -- not a reuse of taint/domain.Label
// -- so this package never imports the taint feature's domain type directly,
// the same "own your full vertical" boundary every other cross-feature
// signal in this Context (JobOverBudget, CostOverBudget) already respects.
type TaintSignal struct {
	Tainted bool
	Sources []string
}

// ParsedRequest is the result of parsing an incoming MCP JSON-RPC
// request body. IsGated distinguishes a policy-evaluated request (Call
// is populated) from a true protocol-lifecycle/discovery method like
// "initialize" or "tools/list" (Method is populated, Call is the zero
// value) that's forwarded to upstream without any evaluation. IsToolCall
// is the narrower "exactly tools/call" signal: every gated request runs
// through policy, but only a tools/call additionally runs through the
// budget checker — see
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md
// for why budget enforcement doesn't widen along with policy.
type ParsedRequest struct {
	Call       ToolCall
	Method     string
	ID         json.RawMessage
	IsToolCall bool
	IsGated    bool
}
