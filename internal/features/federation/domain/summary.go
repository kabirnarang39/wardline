package domain

import (
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// AnomalySummary is the only thing that ever crosses the federation wire
// about a local anomaly: a pseudonymized identity fingerprint, which
// heuristic kind fired, how many times, over what window, and which
// tenant. It deliberately carries no tool name, no detail string, and no
// audit.Entry -- those are dropped before a summary is ever constructed
// (see usecase.Aggregate), not filtered out later.
//
// Tenant is plaintext, not hashed the way Fingerprint is -- tenant names
// are organizational labels Wardline already treats as plaintext
// everywhere else (audit entries, RBAC bindings, the dashboard's own
// tenant-scoped views), not per-identity sensitive the way a raw
// identity string is. Carrying it lets the dashboard's correlated-alerts
// view be tenant-scoped like every other view (see
// rbac.md/RBAC known limitations, which used to document this as a gap)
// and lets Correlator group sightings per-tenant, so two different
// tenants' identically-named identities (the same fingerprint, since
// Fingerprint hashes identity alone) never get folded into one
// correlated alert.
type AnomalySummary struct {
	Fingerprint string
	Tenant      string
	Kind        anomalydomain.Kind
	Count       int
	WindowStart time.Time
	WindowEnd   time.Time
}

// SignedSummaryBatch is the wire shape POSTed to a peer's
// /federation/summaries: one instance's batch of summaries for one
// publish interval, plus a signature over the batch so the receiver can
// verify which configured peer actually sent it.
type SignedSummaryBatch struct {
	InstanceID string
	Summaries  []AnomalySummary
	Signature  []byte
}
