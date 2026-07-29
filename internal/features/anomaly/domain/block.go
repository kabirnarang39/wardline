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
// dashboard's read-only blocked-list endpoint.
type BlockedEntry struct {
	Identity     string    `json:"identity"`
	BlockedUntil time.Time `json:"blocked_until"`
	Reason       string    `json:"reason"`
}
