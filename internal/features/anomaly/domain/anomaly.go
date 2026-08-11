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
	KindDrift         Kind = "drift_detection"
	KindTenantDrift   Kind = "tenant_aggregate_spike"
	KindIdentityChurn Kind = "identity_churn"
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

	// Score is the detector's own magnitude for this anomaly, nil for a
	// kind that has no real magnitude to report (novel_tool is a binary
	// "first time seen" signal, not a graded score) -- nil must never be
	// papered over with a fabricated 0 or placeholder value, since that
	// would misrepresent "no real score exists" as "scored exactly zero."
	// Only checkMLScore populates it today.
	Score *float64

	// AutoBlockSeconds is the real configured auto-block duration, set
	// only when THIS anomaly is the one that actually triggered a live
	// Block() call (see checkMLScore) -- zero means "did not cause a
	// block," never a guess about what a block *would* have lasted had
	// auto_block been enabled.
	AutoBlockSeconds int
}
