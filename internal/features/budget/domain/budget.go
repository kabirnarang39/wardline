package domain

import "time"

// Verdict is the result of checking whether an identity may proceed under
// the current budget.
type Verdict struct {
	Allowed bool
	Reason  string

	// RetryAfter is how long until the caller's window resets. Only
	// meaningful when Allowed is false — never read otherwise.
	RetryAfter time.Duration

	// FailedOpen marks an Allowed verdict that was granted *without* the
	// budget actually being checked, because a Postgres-backed Limiter hit
	// a genuine backend error and chose availability over enforcement.
	// Only ever true alongside Allowed — it exists so callers can record
	// "enforcement was skipped" durably (in the audit trail) instead of
	// leaving a single Warn log line as the only trace. InMemoryLimiter
	// never sets it: an in-process map has no backend to fail.
	FailedOpen bool
}

// Limiter decides whether an identity may make another call right now.
// tenant is the identity's resolved tenant; an empty tenant (or one with no
// configured override) is simply not checked against any tenant-level
// bucket. tool is the MCP tool being called; a tool with no configured
// override is likewise never checked against any tool-level bucket.
type Limiter interface {
	Allow(identity, tenant, tool string, now time.Time) Verdict
}
