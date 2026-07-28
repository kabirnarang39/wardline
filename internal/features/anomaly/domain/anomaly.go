package domain

import (
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// Kind identifies which heuristic produced an Anomaly.
type Kind string

const (
	KindRateSpike     Kind = "rate_spike"
	KindNovelTool     Kind = "novel_tool"
	KindDenyRateSpike Kind = "deny_rate_spike"
)

// Anomaly is one flagged behavioral signal: an identity did something
// that heuristically doesn't match its own recent history. Entry is the
// audit record that triggered the detection, kept so a log line or
// dashboard view can show exactly which call raised the flag without a
// second lookup.
type Anomaly struct {
	Timestamp time.Time
	Identity  string
	Kind      Kind
	Detail    string
	Entry     auditdomain.Entry
}
