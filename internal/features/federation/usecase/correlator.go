package usecase

import (
	"sort"
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// fingerprintState tracks, for one (fingerprint, kind) pair, which
// instance IDs have reported a sighting and when each was last seen.
// flaggedAt records when a CorrelatedAlert was last emitted for this
// pair (zero means never); it re-arms once a full correlation window has
// elapsed since that alert, so a sustained cross-instance condition
// produces one alert per window, not one per state lifetime -- matching
// the design spec's "once per fingerprint per window" and the same
// per-window reset anomaly detection's own Detector already applies,
// rather than latching forever until GC eviction (20 min of total
// silence by default).
type fingerprintState struct {
	instances map[string]time.Time
	flaggedAt time.Time
}

// Correlator watches inbound AnomalySummary sightings (this instance's
// own local anomalies flow through it too, via the same Ingest call
// main.go wires -- see design doc) and emits a CorrelatedAlert when a
// (tenant, fingerprint) pair has been sighted by enough distinct
// instances within the configured correlation window. In-memory,
// mutex-guarded, GC'd by StartCorrelatorGC -- no persistence this cycle.
type Correlator struct {
	cfg     domain.FederationConfig
	onAlert func(domain.CorrelatedAlert)
	now     func() time.Time

	mu sync.Mutex
	// state is keyed by tenant.Key(s.Tenant, s.Fingerprint), not
	// Fingerprint alone -- see AnomalySummary's own doc comment on why:
	// two different tenants' identically-named identities hash to the
	// SAME fingerprint (Fingerprint is identity-only), so without the
	// tenant folded into this key they'd incorrectly correlate as one
	// condition. tenant.Key's length-prefixed composition (not a plain
	// separator join) is what makes that safe regardless of what
	// characters either string contains -- same reasoning as
	// credential/adapter.postgresSafeKey's own doc comment.
	state map[string]map[string]*fingerprintState // tenant.Key(tenant, fingerprint) -> kind (as string) -> state
}

func NewCorrelator(cfg domain.FederationConfig, onAlert func(domain.CorrelatedAlert), now func() time.Time) *Correlator {
	return &Correlator{
		cfg:     cfg,
		onAlert: onAlert,
		now:     now,
		state:   make(map[string]map[string]*fingerprintState),
	}
}

// Ingest records one instance's sighting of one AnomalySummary and
// evaluates whether the min-instances/window threshold is now met.
// Never blocks or errors outward -- the caller (Handler, or main.go for
// this instance's own local anomalies) must be able to call this from a
// hot path without any risk of it stalling.
//
// State is mutated under c.mu in recordAndCheck, then onAlert (a
// caller-supplied callback we don't control the speed of) is invoked
// only after the lock is released -- same split as
// anomaly/usecase.Detector.Publish, and for the same reason: a slow
// onAlert must only stall this call, never serialize every other
// instance's concurrent Ingest behind it.
func (c *Correlator) Ingest(instanceID string, s domain.AnomalySummary) {
	if alert, ok := c.recordAndCheck(instanceID, s); ok {
		c.onAlert(alert)
	}
}

func (c *Correlator) recordAndCheck(instanceID string, s domain.AnomalySummary) (domain.CorrelatedAlert, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stateKey := tenant.Key(s.Tenant, s.Fingerprint)
	byKind, ok := c.state[stateKey]
	if !ok {
		byKind = make(map[string]*fingerprintState)
		c.state[stateKey] = byKind
	}
	kindKey := string(s.Kind)
	st, ok := byKind[kindKey]
	if !ok {
		st = &fingerprintState{instances: make(map[string]time.Time)}
		byKind[kindKey] = st
	}
	now := c.now()
	st.instances[instanceID] = now

	window := time.Duration(c.cfg.CorrelationWindowSeconds) * time.Second

	// Re-arm only once a full window has elapsed since the last alert for
	// this fingerprint/kind -- before that, this is the same correlated
	// condition already reported, not a new one.
	if !st.flaggedAt.IsZero() && now.Sub(st.flaggedAt) < window {
		return domain.CorrelatedAlert{}, false
	}

	cutoff := now.Add(-window)
	var distinct []string
	var firstSeen time.Time
	for id, seen := range st.instances {
		if seen.After(cutoff) {
			distinct = append(distinct, id)
			if firstSeen.IsZero() || seen.Before(firstSeen) {
				firstSeen = seen
			}
		}
	}

	if len(distinct) < c.cfg.MinInstancesForCorrelation {
		return domain.CorrelatedAlert{}, false
	}

	// map iteration order is nondeterministic and InstanceIDs is now
	// user-facing JSON via the dashboard -- sort for a stable, readable
	// wire shape.
	sort.Strings(distinct)

	st.flaggedAt = now
	return domain.CorrelatedAlert{
		Fingerprint: s.Fingerprint,
		Tenant:      s.Tenant,
		Kind:        s.Kind,
		InstanceIDs: distinct,
		FirstSeen:   firstSeen,
		LastSeen:    now,
	}, true
}
