package domain

import "time"

// Entry is one audit record: what identity tried to call what tool, and
// what happened.
type Entry struct {
	Timestamp time.Time
	Identity  string

	// Tenant is the calling identity's tenant, resolved by
	// IdentityAuthenticator alongside Identity (see
	// proxydomain.ToolCall.Tenant). "" means no tenant scoping applied.
	Tenant string

	Tool string
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
