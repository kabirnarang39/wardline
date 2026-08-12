package domain

import (
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// CorrelatedAlert is emitted when the same (tenant, identity fingerprint)
// pair has been sighted (by this instance's own local detection, by a
// peer, or both) tripping the same anomaly Kind across enough distinct
// instances within one correlation window to no longer look like
// independent coincidences. Correlation is scoped per-tenant -- see
// AnomalySummary's own doc comment on why Tenant is plaintext and why
// folding it into the correlation key (not just carrying it for
// display) matters: without it, the same identity NAME in two different
// tenants (same Fingerprint, since Fingerprint hashes identity alone)
// would incorrectly correlate as one condition.
type CorrelatedAlert struct {
	Fingerprint string
	Tenant      string
	Kind        anomalydomain.Kind
	InstanceIDs []string
	FirstSeen   time.Time
	LastSeen    time.Time
}
