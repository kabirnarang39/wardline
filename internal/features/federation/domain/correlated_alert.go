package domain

import (
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// CorrelatedAlert is emitted when the same identity fingerprint has
// been sighted (by this instance's own local detection, by a peer, or
// both) tripping the same anomaly Kind across enough distinct instances
// within one correlation window to no longer look like independent
// coincidences.
type CorrelatedAlert struct {
	Fingerprint string
	Kind        anomalydomain.Kind
	InstanceIDs []string
	FirstSeen   time.Time
	LastSeen    time.Time
}
