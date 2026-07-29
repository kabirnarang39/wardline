package domain

import (
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// AnomalySummary is the only thing that ever crosses the federation wire
// about a local anomaly: a pseudonymized identity fingerprint, which
// heuristic kind fired, how many times, and over what window. It
// deliberately carries no tool name, no detail string, and no
// audit.Entry -- those are dropped before a summary is ever constructed
// (see usecase.Aggregate), not filtered out later.
type AnomalySummary struct {
	Fingerprint string
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
