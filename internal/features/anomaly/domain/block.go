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
	BlockedUntil time.Time `json:"blocked_until"`
	Reason       string    `json:"reason"`
}
