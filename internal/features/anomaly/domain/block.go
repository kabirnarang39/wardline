package domain

import "time"

// BlockVerdict is BlockChecker's answer to "may this identity's call
// proceed". Mirrors budget/domain.Verdict's shape exactly -- same
// consuming pattern in proxy/adapter.Handler.
type BlockVerdict struct {
	Allowed    bool
	RetryAfter time.Duration
	Reason     string
}

// BlockedEntry is one currently-blocked identity, as surfaced by the
// dashboard's read-only blocked-list endpoint. Tenant disambiguates
// entries once BlockChecker partitions blocks by (Tenant, Identity) --
// two different tenants' identically-named identities can each appear
// here independently.
type BlockedEntry struct {
	Identity     string    `json:"identity"`
	Tenant       string    `json:"tenant"`
	BlockedSince time.Time `json:"blocked_since"`
	BlockedUntil time.Time `json:"blocked_until"`
	Reason       string    `json:"reason"`
}

// Blocker is the auto-block surface both the in-memory BlockChecker
// (usecase) and the Postgres-backed PostgresBlockStore (adapter, wired
// when postgres_storage is on so a block triggered by one HA replica is
// visible to every other) satisfy. Extracted so cmd/wardline can hold
// either behind one type -- the same Open/Closed pattern PostgresLimiter
// (budget) and PostgresBaselineStore (anomaly baselines) already follow
// for their own per-replica-vs-shared state.
type Blocker interface {
	// Block records (identity, tenantName) as blocked for the configured
	// duration, with reason recorded for the audit entry and dashboard.
	Block(identity, tenantName, reason string)
	// Check reports whether (identity, tenantName) may proceed at now.
	Check(identity, tenantName string, now time.Time) BlockVerdict
	// Unblock clears an active block early; returns whether one was
	// present and still active.
	Unblock(identity, tenantName string) bool
	// List returns every currently-active block, optionally filtered by
	// tenant ("" means unfiltered).
	List(tenantFilter string) []BlockedEntry
}
