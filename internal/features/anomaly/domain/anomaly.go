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
	KindMLScore       Kind = "ml_score"
)

// Anomaly is one flagged behavioral signal: an identity did something
// that heuristically doesn't match its own recent history. Entry is the
// audit record that triggered the detection, kept so a log line or
// dashboard view can show exactly which call raised the flag without a
// second lookup. Tenant is carried alongside Identity because Detector's
// baselines are now partitioned by (Tenant, Identity) -- two different
// tenants' identically-named identities are two entirely independent
// baselines, and this field is what lets a log line or dashboard view
// disambiguate them.
type Anomaly struct {
	Timestamp time.Time
	Identity  string
	Tenant    string
	Kind      Kind
	Detail    string
	Entry     auditdomain.Entry
}
