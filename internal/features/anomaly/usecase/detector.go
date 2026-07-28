package usecase

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// alertSink is the subset of AlertBuffer's behavior Detector depends on
// -- declared here (not as the concrete *AlertBuffer type from Task 6)
// so this task compiles standalone with no forward reference; AlertBuffer
// satisfies this interface structurally once Task 6 defines it.
type alertSink interface {
	Add(domain.Anomaly)
}

// Detector implements audit/domain.LiveSink: every published audit entry
// is run through all enabled heuristics. Publish must never block or
// error outward -- the same contract every other LiveSink already
// guarantees -- so a Writer failure goes to onError (logged) rather than
// propagating to the caller (the audit Recorder itself).
type Detector struct {
	cfg     domain.HeuristicConfig
	writer  domain.Writer
	buffer  alertSink
	onError func(error)
	now     func() time.Time

	mu    sync.Mutex
	state map[string]*identityState
}

func NewDetector(cfg domain.HeuristicConfig, writer domain.Writer, buffer alertSink, onError func(error), now func() time.Time) *Detector {
	return &Detector{
		cfg:     cfg,
		writer:  writer,
		buffer:  buffer,
		onError: onError,
		now:     now,
		state:   make(map[string]*identityState),
	}
}

var _ auditdomain.LiveSink = (*Detector)(nil)

// Publish mutates per-identity state under d.mu, then emits any resulting
// anomalies after releasing the lock -- a slow Writer.Write must only
// stall the caller's own Publish, never serialize every other identity's
// concurrent Publish calls behind it.
func (d *Detector) Publish(e auditdomain.Entry) {
	toEmit := d.recordAndCheck(e)
	for _, a := range toEmit {
		d.emit(a)
	}
}

func (d *Detector) recordAndCheck(e auditdomain.Entry) []domain.Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	st, ok := d.state[e.Identity]
	if !ok {
		st = &identityState{tools: make(map[string]struct{}), windowStart: now}
		d.state[e.Identity] = st
	}
	st.lastSeen = now

	window := time.Duration(d.cfg.WindowSeconds) * time.Second
	if now.Sub(st.windowStart) >= window {
		st.prev = st.cur
		st.cur = windowCounts{}
		st.windowStart = now
		st.flaggedThisWindow = nil
	}

	st.cur.total++
	if e.Decision == "deny" {
		st.cur.deny++
	}

	var toEmit []domain.Anomaly
	if d.cfg.RateSpikeEnabled {
		if a, ok := d.checkRateSpike(e, st); ok {
			toEmit = append(toEmit, a)
		}
	}
	return toEmit
}

// checkRateSpike must be called with d.mu held (st is shared, mutable
// state). It latches on st.flaggedThisWindow so a sustained spike emits
// exactly one Anomaly per window, not one per call above threshold.
func (d *Detector) checkRateSpike(e auditdomain.Entry, st *identityState) (domain.Anomaly, bool) {
	if st.prev.total == 0 {
		return domain.Anomaly{}, false // no baseline yet -- nothing to compare against
	}
	if st.cur.total < d.cfg.RateMinCalls {
		return domain.Anomaly{}, false
	}
	threshold := float64(st.prev.total) * d.cfg.RateMultiplier
	if float64(st.cur.total) <= threshold {
		return domain.Anomaly{}, false
	}
	if st.flaggedThisWindow[domain.KindRateSpike] {
		return domain.Anomaly{}, false
	}
	if st.flaggedThisWindow == nil {
		st.flaggedThisWindow = make(map[domain.Kind]bool)
	}
	st.flaggedThisWindow[domain.KindRateSpike] = true
	return domain.Anomaly{
		Timestamp: d.now(),
		Identity:  e.Identity,
		Kind:      domain.KindRateSpike,
		Detail:    "call rate exceeded the identity's own trailing baseline",
		Entry:     e,
	}, true
}

func (d *Detector) emit(a domain.Anomaly) {
	if err := d.writer.Write(a); err != nil && d.onError != nil {
		d.onError(err)
	}
	if d.buffer != nil {
		d.buffer.Add(a)
	}
}
