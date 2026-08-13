package domain

import (
	"context"
	"time"
)

// Entry is one audit record: what identity tried to call what tool, and
// what happened.
type Entry struct {
	Timestamp time.Time
	Identity  string

	// Tenant is the calling identity's tenant, resolved by
	// IdentityAuthenticator alongside Identity (see
	// proxydomain.ToolCall.Tenant). "" means no tenant scoping applied.
	Tenant string

	Tool      string
	Decision  string // "allow", "deny", "throttled", "passthrough", "error", or "blocked"
	LatencyMS int64

	// Reason is the detailed, potentially sensitive explanation behind a
	// decision (e.g. a policy engine's internal error text, file paths,
	// or rule names). It's recorded here for the operator only — never
	// sent to the untrusted HTTP caller.
	Reason string

	// TraceID correlates this entry with a distributed trace, when OTel
	// tracing is enabled. Empty when tracing is disabled — no all-zero
	// placeholder IDs cluttering the audit log.
	TraceID string

	// Effect records, for a write-shaped gated call, the change the call
	// claimed to make plus the proxy-visible signal from the upstream
	// response. nil for reads/lifecycle calls and for every pre-Effect
	// entry. Observe-only: it never affects a decision.
	Effect *Effect

	// EffectStatus is the classification derived from Effect; empty when no
	// Effect was recorded.
	EffectStatus EffectStatus

	// SessionID is the explicit X-Wardline-Session for this call, when the
	// caller sent one. Empty when absent (the taint engine then falls back
	// to its TTL window). Optional/additive — omitempty in serialization.
	SessionID string

	// TaintSources names the untrusted-source tool(s) that tainted this
	// call's (tenant, identity, session) at decision time, when
	// taint_tracking is on and the session was tainted -- nil otherwise.
	// Recorded regardless of Decision: an allowed call under taint is
	// exactly as worth surfacing here as a denied one, since policy (not
	// this field) is what decided whether taint mattered. Same
	// optional/additive scope as SessionID -- JSONL only for now, not yet
	// carried by the Postgres writer or the dashboard's LiveEntry.
	TaintSources []string
}

// EffectStatus classifies whether a write-shaped call's claimed change was
// confirmed, left unconfirmed, or contradicted by the proxy-visible response.
type EffectStatus string

const (
	EffectStatusConfirmed    EffectStatus = "claimed_and_confirmed"
	EffectStatusUnconfirmed  EffectStatus = "claimed_but_unconfirmed"
	EffectStatusContradicted EffectStatus = "claimed_but_contradicted"
	EffectStatusNotAWrite    EffectStatus = "not_a_write"
)

// Effect captures the change a gated call claimed to make and the
// proxy-visible signal from the upstream response. A proxy sees request and
// response but not world-state, so this is a boundary signal, not a semantic
// guarantee — a true claimed-vs-actual diff is the PostConditionVerifier's
// (Stage 2) job.
type Effect struct {
	Target      string            // resource URI / tool target
	ClaimedOp   string            // tool or method name
	ClaimedArgs map[string]string // redacted mutating params

	ResponseStatus int  // upstream transport status
	RPCError       bool // JSON-RPC error present in the response
	NoOpSignal     bool // proxy-visible no-op / empty result / success:false
}

// Verdict is a PostConditionVerifier's answer for a claimed effect.
type Verdict string

const (
	VerdictConfirmed    Verdict = "confirmed"
	VerdictContradicted Verdict = "contradicted"
	VerdictUnknown      Verdict = "unknown"
)

// PostConditionVerifier consults actual state for an entry's claimed effect
// and returns a verdict. It runs out of band (never in the request path).
// Stage 2 seam — declared so Stage 1's data model is shaped to feed it; no
// implementation ships yet.
type PostConditionVerifier interface {
	Verify(ctx context.Context, e Entry) (Verdict, error)
}

// Writer persists an audit Entry.
type Writer interface {
	Write(Entry) error
}

// LiveSink receives a live copy of every recorded Entry, independent of
// the durable Writer. Used by the dashboard feature (when the web_ui flag
// is on) to power its in-memory audit view without tailing the JSONL
// file — Publish must never block or error; a slow or full sink drops
// data rather than affect request handling.
type LiveSink interface {
	Publish(Entry)
}
