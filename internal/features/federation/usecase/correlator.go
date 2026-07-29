package usecase

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

// fingerprintState tracks, for one (fingerprint, kind) pair, which
// instance IDs have reported a sighting and when each was last seen.
// flagged latches once a CorrelatedAlert has been emitted for this
// pair, so a sustained cross-instance condition produces one alert, not
// one per additional sighting -- the same "no flood on sustained
// condition" lesson anomaly detection's own Detector already learned.
type fingerprintState struct {
	instances map[string]time.Time
	flagged   bool
}

// Correlator watches inbound AnomalySummary sightings (this instance's
// own local anomalies flow through it too, via the same Ingest call
// main.go wires -- see design doc) and emits a CorrelatedAlert when a
// fingerprint has been sighted by enough distinct instances within the
// configured correlation window. In-memory, mutex-guarded, GC'd by
// StartCorrelatorGC -- no persistence this cycle.
type Correlator struct {
	cfg     domain.FederationConfig
	onAlert func(domain.CorrelatedAlert)
	now     func() time.Time

	mu    sync.Mutex
	state map[string]map[string]*fingerprintState // fingerprint -> kind (as string) -> state
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

	byKind, ok := c.state[s.Fingerprint]
	if !ok {
		byKind = make(map[string]*fingerprintState)
		c.state[s.Fingerprint] = byKind
	}
	kindKey := string(s.Kind)
	st, ok := byKind[kindKey]
	if !ok {
		st = &fingerprintState{instances: make(map[string]time.Time)}
		byKind[kindKey] = st
	}
	st.instances[instanceID] = c.now()

	if st.flagged {
		return domain.CorrelatedAlert{}, false
	}

	window := time.Duration(c.cfg.CorrelationWindowSeconds) * time.Second
	cutoff := c.now().Add(-window)
	var distinct []string
	for id, seen := range st.instances {
		if seen.After(cutoff) {
			distinct = append(distinct, id)
		}
	}

	if len(distinct) < c.cfg.MinInstancesForCorrelation {
		return domain.CorrelatedAlert{}, false
	}

	st.flagged = true
	return domain.CorrelatedAlert{
		Fingerprint: s.Fingerprint,
		Kind:        s.Kind,
		InstanceIDs: distinct,
		FirstSeen:   cutoff,
		LastSeen:    c.now(),
	}, true
}
