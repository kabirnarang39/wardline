package usecase

import (
	"fmt"
	"math"
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

// blocker is the subset of usecase.BlockChecker's behavior Detector
// depends on -- one method, matching alertSink's narrow-interface
// pattern. nil-able: ml_score-without-auto_block needs zero special-casing
// here beyond a nil check. tenantName is threaded through so Block keys
// on (tenant, identity), not identity alone -- see tenantIdentityKey.
type blocker interface {
	Block(identity, tenantName, reason string)
}

// baselineStore is the subset of adapter.PostgresBaselineStore's
// behavior Detector depends on -- narrow local interface (matching
// alertSink/blocker's established pattern in this same file) so this
// package never imports internal/features/anomaly/adapter directly.
// nil-able: when nil, Detector behaves exactly as it did before this
// plan (in-memory only, LoadBaselines is a no-op, gc never calls
// SaveAll).
type baselineStore interface {
	LoadAll() (map[string]IdentityStateSnapshot, error)
	SaveAll(snapshots map[string]IdentityStateSnapshot, deletedKeys []string) error
}

// tenantWindowStore is the narrow interface PostgresTenantWindowStore
// satisfies -- an atomic add-and-read for one tenant's current window
// total, genuinely shared across replicas. nil-able: when nil,
// checkTenantDrift scores only this replica's own local total (today's
// behavior, unchanged).
type tenantWindowStore interface {
	AddAndGet(tenantName string, windowStart time.Time, delta int) (int, error)
}

// tenantBaselineStoreIface is the narrow interface
// PostgresTenantBaselineStore satisfies -- per-instance restart
// persistence for tenant baselines, deliberately NOT the same sharing
// model as tenantWindowStore: every replica converges to the same
// baseline by folding the same cross-replica-*merged* total (see
// checkTenantDrift), not by reading each other's baseline rows. Named
// with an Iface suffix only to avoid colliding with the
// tenantBaselineStore field name Detector needs below.
type tenantBaselineStoreIface interface {
	LoadAll() (map[string]OnlineStatSnapshot, error)
	SaveAll(baselines map[string]OnlineStatSnapshot) error
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
	blocker blocker
	onError func(error)
	now     func() time.Time
	store   baselineStore

	mu sync.Mutex
	// state is keyed by tenantIdentityKey(tenant, identity), not by raw
	// identity -- two different tenants' identically-named identities
	// (two SCIM-provisioned "alice"s from different IdPs) must never
	// share a baseline. Every read, write, and iteration of this map
	// must go through tenantIdentityKey.
	state map[string]*identityState

	// tenantState is TenantAnomaly's aggregate-per-tenant baseline --
	// keyed by tenant alone (never composed via tenantIdentityKey; there
	// is no identity component), lazily initialized on first use. See
	// checkTenantDrift/tenant_detector.go.
	tenantState map[string]*tenantWindowState

	// churnState is IdentityChurn's aggregate-per-tenant new-identity-
	// count baseline -- deliberately its own map, not folded into
	// tenantState (see churnWindowState's own doc comment for why).
	// Lazily initialized on first use. See
	// checkIdentityChurn/identity_churn_detector.go.
	churnState map[string]*churnWindowState

	// tenantWindowStorePg/tenantBaselineStorePg are nil-able -- see
	// their interface types' doc comments for what each does and does
	// NOT share across replicas.
	tenantWindowStorePg   tenantWindowStore
	tenantBaselineStorePg tenantBaselineStoreIface
}

func NewDetector(cfg domain.HeuristicConfig, writer domain.Writer, buffer alertSink, blocker blocker, onError func(error), now func() time.Time, store baselineStore) *Detector {
	return &Detector{
		cfg:     cfg,
		writer:  writer,
		buffer:  buffer,
		blocker: blocker,
		onError: onError,
		now:     now,
		store:   store,
		state:   make(map[string]*identityState),
	}
}

// LoadBaselines populates d.state from the configured baseline store, if
// any -- a no-op returning nil when store is nil. Intended to be called
// once, synchronously, by the composition root (cmd/wardline/main.go)
// immediately after NewDetector and before StartGC begins -- this IS
// allowed to block briefly (see this plan's Global Constraints), unlike
// Publish. Not called from NewDetector itself, so NewDetector stays a
// pure, non-blocking constructor.
func (d *Detector) LoadBaselines() error {
	if d.store == nil {
		return nil
	}
	snapshots, err := d.store.LoadAll()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, snap := range snapshots {
		d.state[key] = snap.toIdentityState()
	}
	return nil
}

// NewDetectorWithTenantStores is NewDetector plus the two optional
// Postgres-backed tenant_anomaly stores (see their interface types'
// doc comments above). NewDetector itself stays untouched -- every
// existing call site (production and test) that doesn't need
// HA-shared tenant state keeps working exactly as before; only
// main.go's postgres_storage + tenant_anomaly.enabled branch needs
// this one.
func NewDetectorWithTenantStores(cfg domain.HeuristicConfig, writer domain.Writer, buffer alertSink, blocker blocker, onError func(error), now func() time.Time, store baselineStore, tenantWindows tenantWindowStore, tenantBaselines tenantBaselineStoreIface) *Detector {
	d := NewDetector(cfg, writer, buffer, blocker, onError, now, store)
	d.tenantWindowStorePg = tenantWindows
	d.tenantBaselineStorePg = tenantBaselines
	return d
}

// LoadTenantBaselines populates each tenant's rateStat from
// tenantBaselineStorePg, if any -- a no-op returning nil when nil.
// Mirrors LoadBaselines' exact calling convention: called once,
// synchronously, by the composition root immediately after
// NewDetectorWithTenantStores and before StartGC begins.
func (d *Detector) LoadTenantBaselines() error {
	if d.tenantBaselineStorePg == nil {
		return nil
	}
	snapshots, err := d.tenantBaselineStorePg.LoadAll()
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tenantState == nil {
		d.tenantState = make(map[string]*tenantWindowState)
	}
	for tenantName, snap := range snapshots {
		ts, ok := d.tenantState[tenantName]
		if !ok {
			ts = &tenantWindowState{}
			d.tenantState[tenantName] = ts
		}
		ts.rateStat = onlineStat{mean: snap.Mean, m2: snap.M2, count: snap.Count}
	}
	return nil
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

// isToolCall reports whether e records a policy-evaluated tool call, as
// opposed to the two other kinds of entry proxy/adapter.Handler writes:
//
//   - MCP protocol-lifecycle methods (decision "passthrough", Tool set to
//     the method name -- "initialize", "notifications/initialized",
//     "tools/list"). Every real MCP client sends these before its first
//     tool call, so treating them as tools would flag three brand-new
//     "novel tools" for every identity on every restart -- guaranteed
//     false positives, exactly the alert fatigue a detect-and-log feature
//     cannot afford.
//   - Tool-less failures (decision "error", Tool "") recorded when the
//     body is unreadable or the JSON-RPC envelope is unparsable. These
//     would emit a novel_tool anomaly whose tool name is the empty string.
//
// Neither kind is a tool call, so neither may reach the novel-tool set or
// deny-rate-spike's denominator (protocol chatter in that denominator
// dilutes the deny ratio and can suppress a real deny spike). Both are
// still counted in windowCounts.total: rate-spike is deliberately
// volumetric over *all* of an identity's traffic.
func isToolCall(e auditdomain.Entry) bool {
	return e.Tool != "" && e.Decision != "passthrough"
}

func (d *Detector) recordAndCheck(e auditdomain.Entry) []domain.Anomaly {
	// A "blocked" decision is Wardline's own auto-block gate rejecting the
	// call before it ever reaches policy -- self-inflicted rejection
	// traffic from an identity that's already been flagged, not a real
	// behavioral signal. Feeding it into window state would let it
	// re-poison the very heuristics that produced the block: a retrying
	// client's rejected calls would inflate the rate/inter-arrival
	// features, and a client that backs off would produce a near-empty
	// window (see checkMLScore's MinCalls gate) -- either way
	// re-triggering Block() at every rollover, forever, which is exactly
	// what "strictly time-bounded" promises won't happen. Excluding these
	// entries entirely means the first real call after the block expires
	// is scored exactly as if the blocked period never happened. This
	// applies to every heuristic, not just ml_score: a blocked call is not
	// real traffic for rate_spike, novel_tool or deny_rate_spike either.
	// Nothing is read or written for this case, so the guard sits ahead of
	// the mutex.
	if e.Decision == "blocked" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	key := tenantIdentityKey(e.Tenant, e.Identity)
	st, ok := d.state[key]
	// isNewIdentity must be read from the same lookup recordAndCheck
	// already does above -- a second, later check against d.state would
	// always see !ok == false (this call's own st = &identityState{...}
	// just below made it exist), so "new" has to be captured here, at
	// this exact point, or it can never be true again.
	isNewIdentity := !ok
	if !ok {
		st = &identityState{tools: make(map[string]struct{}), windowStart: now}
		d.state[key] = st
	}
	st.lastSeen = now

	window := time.Duration(d.cfg.WindowSeconds) * time.Second
	windowJustCompleted := now.Sub(st.windowStart) >= window
	if windowJustCompleted {
		st.prev = st.cur
		st.cur = windowCounts{}
		st.windowStart = now
		st.flaggedThisWindow = nil
		st.lastCallAt = time.Time{} // first call of a new window has no in-window predecessor
	}

	st.cur.total++
	if isToolCall(e) {
		st.cur.toolCalls++
		if e.Decision == "deny" {
			st.cur.deny++
		}
		if st.cur.uniqueTools == nil {
			st.cur.uniqueTools = make(map[string]struct{})
		}
		st.cur.uniqueTools[e.Tool] = struct{}{}
	}
	if !st.lastCallAt.IsZero() {
		st.cur.interArrivalSum += now.Sub(st.lastCallAt)
		st.cur.interArrivalN++
	}
	st.lastCallAt = now

	var toEmit []domain.Anomaly
	if d.cfg.RateSpikeEnabled {
		if a, ok := d.checkRateSpike(e, st); ok {
			toEmit = append(toEmit, a)
		}
	}
	if d.cfg.NovelToolEnabled {
		if a, ok := d.checkNovelTool(e, st); ok {
			toEmit = append(toEmit, a)
		}
	}
	if d.cfg.DenyRateSpikeEnabled {
		if a, ok := d.checkDenyRateSpike(e, st); ok {
			toEmit = append(toEmit, a)
		}
	}
	// ml_score is different from the three checks above: it scores a
	// window only once, at the instant it just completed (st.prev), never
	// the in-progress st.cur -- see checkMLScore's doc comment. Gating on
	// windowJustCompleted (true for exactly one Publish call per window,
	// the call whose arrival crosses the boundary) is what makes that
	// "once" hold; calling checkMLScore unconditionally on every Publish
	// call like the other three heuristics would re-score the same
	// completed window -- and re-fold its raw feature values into
	// st.mlStats -- once per call in the *following* window, silently
	// over-weighting whichever window happens to contain the most calls.
	if d.cfg.MLScore.Enabled && windowJustCompleted {
		// checkDrift runs before checkMLScore, not after: it reads
		// mlStats.rate's baseline via zCount exactly as checkMLScore's own
		// zRate does, and checkMLScore conditionally folds this window's
		// rate into that same baseline at the end of its own body. Calling
		// checkDrift first guarantees it always sees the pre-fold
		// baseline -- the same one zRate is computed against -- rather
		// than one that (whenever this window wasn't itself flagged by
		// ml_score) already includes this window's own value.
		if d.cfg.Drift.Enabled {
			toEmit = append(toEmit, d.checkDrift(e, st)...)
		}
		if a, ok := d.checkMLScore(e, st); ok {
			toEmit = append(toEmit, a)
		}
	}

	// Tenant-aggregate detection runs on its own, tenant-scoped window
	// boundary -- independent of windowJustCompleted above, which is
	// this entry's *identity's* window. See checkTenantDrift's doc
	// comment.
	if d.cfg.TenantAnomaly.Enabled {
		if a := d.checkTenantDrift(e); a != nil {
			toEmit = append(toEmit, *a)
		}
	}
	// Same "own tenant-scoped window, independent of any identity's
	// window" reasoning as tenant_anomaly above -- but only accumulated
	// on a genuine first sighting, never every call, since the whole
	// signal is "how many NEW identities," not "how much traffic."
	if d.cfg.IdentityChurn.Enabled && isNewIdentity {
		if a := d.checkIdentityChurn(e.Tenant, now); a != nil {
			toEmit = append(toEmit, *a)
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
		Tenant:    e.Tenant,
		Kind:      domain.KindRateSpike,
		Detail:    "call rate exceeded the identity's own trailing baseline",
		Entry:     e,
	}, true
}

// checkNovelTool must be called with d.mu held (st is shared, mutable
// state). st.tools is itself a one-shot latch per tool: the first call
// records it and fires, every later call to the same tool is a no-op --
// no flaggedThisWindow bookkeeping needed.
func (d *Detector) checkNovelTool(e auditdomain.Entry, st *identityState) (domain.Anomaly, bool) {
	if !isToolCall(e) {
		return domain.Anomaly{}, false
	}
	if _, seen := st.tools[e.Tool]; seen {
		return domain.Anomaly{}, false
	}
	st.tools[e.Tool] = struct{}{}
	return domain.Anomaly{
		Timestamp: d.now(),
		Identity:  e.Identity,
		Tenant:    e.Tenant,
		Kind:      domain.KindNovelTool,
		Detail:    "first call from this identity to tool " + e.Tool,
		Entry:     e,
	}, true
}

// checkDenyRateSpike must be called with d.mu held (st is shared,
// mutable state). Like checkRateSpike, it latches on
// st.flaggedThisWindow (keyed by KindDenyRateSpike) so a sustained deny
// spike emits exactly one Anomaly per window, not one per deny call.
func (d *Detector) checkDenyRateSpike(e auditdomain.Entry, st *identityState) (domain.Anomaly, bool) {
	// toolCalls == 0 is checked separately from the floor: a
	// DenyRateMinCalls of 0 (config validation rejects it, but Detector is
	// constructible directly) would otherwise divide 0 by 0 into NaN, and
	// "NaN <= threshold" is false -- i.e. it would flag on zero traffic.
	if st.cur.toolCalls == 0 || st.cur.toolCalls < d.cfg.DenyRateMinCalls {
		return domain.Anomaly{}, false
	}
	ratio := float64(st.cur.deny) / float64(st.cur.toolCalls)
	if ratio <= d.cfg.DenyRateThreshold {
		return domain.Anomaly{}, false
	}
	if st.flaggedThisWindow[domain.KindDenyRateSpike] {
		return domain.Anomaly{}, false
	}
	if st.flaggedThisWindow == nil {
		st.flaggedThisWindow = make(map[domain.Kind]bool)
	}
	st.flaggedThisWindow[domain.KindDenyRateSpike] = true
	return domain.Anomaly{
		Timestamp: d.now(),
		Identity:  e.Identity,
		Tenant:    e.Tenant,
		Kind:      domain.KindDenyRateSpike,
		Detail:    "deny ratio exceeded threshold within the trailing window",
		Entry:     e,
	}, true
}

// zCount scores a per-window integer-count feature (call_rate,
// tool_diversity) against its running baseline s, flooring the effective
// stddev at max(1.0, sqrt(mean)).
//
// One whole unit alone (round 10's floor) is the smallest floor that makes
// sense for an integer count: it is the smallest amount such a feature can
// move by at all, and the relative floor minStddevRelFraction*mean sits
// below that quantum whenever the baseline mean is small, at which point the
// smallest possible real change already scores as a multi-sigma event. But a
// count's own natural sampling noise is Poisson-like -- stddev on the order
// of sqrt(mean) -- which exceeds 1.0 for any mean above 1, so a bare 1.0
// floor is only actually binding at the smallest baselines (round 10's own
// target, mean 1-3) and under-floors relative to the feature's own
// variability above that. Round 11: a baseline of 3 calls/window jumping to
// 8 in one window scored z=5.0 with a 1.0 floor -- past the 4.0 block
// threshold, for a 2.67x burst the shipped rate_spike heuristic's own
// default 3.0x multiplier would not even flag -- versus z=2.89 with this
// floor, correctly below both thresholds.
//
// Sharing one definition between call_rate and tool_diversity (round 10
// introduced two independent literal-1.0 call sites) also closes the risk of
// the two floors silently drifting apart in a future edit. The floor is
// monotonically at least as large as round 10's, so this can only ever lower
// a z-score: no previously-safe scenario can newly become a false block.
func zCount(s *onlineStat, x float64) float64 {
	return s.ZScoreFloored(x, math.Max(1.0, math.Sqrt(math.Abs(s.mean))))
}

// denyRatioContinuityWeight is deny_ratio's block-gating continuity
// correction's fixed pseudo-observation weight (see the comment above
// pSmoothed in checkMLScore) -- floors the assumed baseline deny
// probability at roughly 1/(2*(denyRatioContinuityWeight+1)) when the
// true historical baseline is p=0. Deliberately its own constant, not a
// reuse of minSamplesForZScore: the two answer unrelated questions
// (this one calibrates a continuity-correction prior; minSamplesForZScore
// gates how many completed windows a baseline needs before its own
// sample stddev is trustworthy), and a future change to
// minSamplesForZScore for ITS documented purpose must not silently move
// this one too. Verified (round 12): raising minSamplesForZScore from 8
// to 20 for its own purpose would, if this constant were still tied to
// it, re-open round 11's exact bug (a 20-call window with 3 habitual
// denials would cross the 4.0 block threshold again). The numeric value
// (8) is unchanged from round 11's choice -- only its identity as an
// independent constant is new.
const denyRatioContinuityWeight = 8

// checkDrift must be called with d.mu held, only once per completed
// window (see checkMLScore's own doc comment for why windowJustCompleted
// gating matters), and before checkMLScore in the same call (see
// recordAndCheck) so it reads mlStats.rate's baseline pre-fold. Requires
// MLScore.Enabled -- see DriftConfig's doc comment for why.
//
// Implements a one-sided CUSUM (cumulative sum) control chart over
// call_rate: the standard, decades-proven statistical-process-control
// technique for exactly the gap a per-window z-score test like
// ml_score's own zRate cannot close (see DriftConfig's doc comment,
// docs/features/anomaly-detection.md's "Known limitations" and "Recall
// benchmark" sections, and TestDetector_AutoBlock_LowAndSlowEvades).
//
//	S_t = max(0, S_{t-1} + z_t - K); alarms when S_t > H
//
// z_t is this window's call_rate deviation, scored through the exact
// same zCount helper (and the exact same mlStats.rate baseline) zRate
// already uses in checkMLScore -- one shared baseline, not a duplicated
// one. The accumulator (identityState.driftCUSUM) resets to 0 both when
// it would go negative (a below-allowance window shouldn't bank
// "credit" that cancels out a future gradual rise, it should simply
// stop accumulating) and after every alarm (standard post-alarm CUSUM
// reset: monitoring restarts for the next drift rather than staying
// pinned at an ever-growing value for as long as a sustained shift
// continues).
func (d *Detector) checkDrift(e auditdomain.Entry, st *identityState) []domain.Anomaly {
	if st.prev.total < d.cfg.Drift.MinCalls {
		return nil
	}
	h := driftEffectiveH(e.Identity, d.cfg.Drift)

	var anomalies []domain.Anomaly
	if a, ok := d.checkDriftFeature(e, "call_rate", &st.driftCUSUM,
		zCount(&st.mlStats.rate, float64(st.prev.total)), h); ok {
		anomalies = append(anomalies, a)
	}
	// tool_diversity's CUSUM closes the slow-novel-tool-drip gap
	// TestAdversarialBenchmark_SlowNovelToolDrip measures: novel_tool
	// logs every first-ever sighting unconditionally, but ml_score's own
	// tool_diversity feature only escalates from a burst within one
	// window (see the novel-tool-enumeration recall table) -- a drip of
	// one new tool per window never moves any single window's count far
	// enough. The same small-persistent-deviation shape CUSUM already
	// closes for call_rate applies identically here: it doesn't matter
	// which feature z_t comes from, only that it's standardized.
	if a, ok := d.checkDriftFeature(e, "tool_diversity", &st.driftDiversityCUSUM,
		zCount(&st.mlStats.diversity, float64(len(st.prev.uniqueTools))), h); ok {
		anomalies = append(anomalies, a)
	}
	return anomalies
}

// checkDriftFeature runs one feature's CUSUM update/alarm/reset cycle --
// factored out of checkDrift so call_rate and tool_diversity (identical
// mechanics, different accumulator and z) can't drift apart. cusum is a
// pointer into the caller's own persistent accumulator field.
func (d *Detector) checkDriftFeature(e auditdomain.Entry, feature string, cusum *float64, z, h float64) (domain.Anomaly, bool) {
	*cusum = math.Max(0, *cusum+z-d.cfg.Drift.K)
	if *cusum <= h {
		return domain.Anomaly{}, false
	}
	fired := *cusum
	*cusum = 0 // post-alarm reset -- see checkDrift's doc comment

	var autoBlockSeconds int
	if d.cfg.AutoBlock.Enabled && d.blocker != nil {
		d.blocker.Block(e.Identity, e.Tenant, fmt.Sprintf(
			"drift_detection cusum %.2f exceeded decision threshold %.2f over a sustained rise in %s",
			fired, h, feature))
		autoBlockSeconds = d.cfg.AutoBlock.BlockDurationSeconds
	}
	return domain.Anomaly{
		Timestamp: d.now(),
		Identity:  e.Identity,
		Tenant:    e.Tenant,
		Kind:      domain.KindDrift,
		Detail: fmt.Sprintf(
			"cumulative sustained rise in %s (cusum %.2f) exceeded decision threshold %.2f",
			feature, fired, h),
		Entry:            e,
		Score:            &fired,
		AutoBlockSeconds: autoBlockSeconds,
	}, true
}

// checkMLScore must be called with d.mu held, and only once per completed
// window -- the caller (recordAndCheck) enforces this by gating the call
// on windowJustCompleted rather than invoking it on every entry the way
// checkRateSpike/checkNovelTool/checkDenyRateSpike are. Unlike those three
// (which evaluate the in-progress st.cur on every call), ml_score
// evaluates a window only once, at the moment it just completed
// (st.prev), against each feature's persistent running baseline in
// st.mlStats -- there is no earlier point at which "this window's tool
// diversity" or "this window's mean inter-arrival time" is a finished,
// scoreable number. Each onlineStat is scored against its pre-update
// baseline, and only folded into that baseline afterward if the window
// didn't itself score as anomalous (see the fold-conditionally comment
// below) -- so a wild window is compared against, and never joins, the
// history that's supposed to represent normal behavior.
func (d *Detector) checkMLScore(e auditdomain.Entry, st *identityState) (domain.Anomaly, bool) {
	// ponytail: below this floor, none of the four features are scored
	// or folded -- a quiet window never enters the baseline either,
	// which biases the baseline slightly toward "busy enough" windows
	// over time. Accepted tradeoff: the alternative (scoring degenerate
	// windows at all) is what produced the diversity/inter-arrival false
	// positives this floor exists to close.
	if st.prev.total < d.cfg.MLScore.MinCalls {
		return domain.Anomaly{}, false
	}
	// rate is deliberately volumetric over *all* of this window's traffic,
	// including MCP protocol-lifecycle passthrough (see windowCounts's doc
	// comment in identity_state.go) -- a client reconnecting/handshaking far
	// more often than usual is itself an unusual pattern (a misbehaving or
	// flapping client, or resource exhaustion) worth catching, independent of
	// whether the underlying requests are real tool calls. Investigated in
	// round 7 and confirmed intentional, not a volume-decline-style false
	// positive in the sense the rest of this function's floors exist to
	// close.
	rate := float64(st.prev.total)
	// diversity is the raw count of distinct tools in this window, not
	// distinct/total. A ratio *rises* when call volume drops over an
	// unchanged tool set (the same 5 tools score 0.05 across 100 calls but
	// 0.25 across 20), so a legitimate volume decline walked straight into
	// maxHarmfulZ's rising-diversity direction -- re-entering, through this
	// feature, the exact permanent-lockout failure the one-sided gate
	// closed for call_rate and deny_ratio. A raw count is volume-invariant
	// by construction and rises only when the window really does contain
	// more distinct tools, which is the enumeration signal this feature is
	// here to catch.
	diversity := float64(len(st.prev.uniqueTools))
	var denyRatio float64
	if st.prev.toolCalls > 0 {
		denyRatio = float64(st.prev.deny) / float64(st.prev.toolCalls)
	}
	var interArrival float64
	if st.prev.interArrivalN > 0 {
		interArrival = st.prev.interArrivalSum.Seconds() / float64(st.prev.interArrivalN)
	}

	// call_rate and tool_diversity are both integer counts, so both are
	// scored through zCount's shared count-aware stddev floor rather than the
	// relative floor alone -- see zCount's doc comment for why, and for the
	// two false positives (one per feature) that floor closes. Flooring one
	// integer-valued feature but not the other would additionally skew which
	// of them leads the score, since the unfloored one keeps an
	// artifact-inflated z: cmd/wardline's ml_score e2e baseline (2-3 calls
	// over 1-2 distinct tools per window) has both features in that zone.
	zRate := zCount(&st.mlStats.rate, rate)

	// diversity, deny_ratio (both zDeny and zDenyBlock), and toolCalls all
	// require a baseline built from windows that actually contained real
	// tool calls -- their signal is undefined, not just "quiet", when a
	// window has none. The MinCalls gate above only checks prev.total,
	// which protocol passthrough and tool-less error entries can clear on
	// their own with zero real tool calls in the window (see isToolCall's
	// doc comment: both are counted in total but excluded from toolCalls).
	// Scoring or folding these three features from such a window pins
	// their baselines at mean 0 -- and the very next legitimate window with
	// real tool calls then reads as a wild outlier by construction (round
	// 12: 12 windows of pure tools/list passthrough, then one real 5-tool
	// window, scored z=5.00 and auto-blocked; because the window is then
	// flagged anomalous it never folds, so the false block repeats forever,
	// the same permanent-lockout failure class every prior round has fixed
	// for a different feature). Gating these three on toolCalls clearing
	// MinCalls too -- the same threshold zDenyBlock already used, now
	// applied consistently -- means a tool-call-free window contributes
	// nothing to any of the three baselines, and the first real window
	// afterward is scored against whatever real history came before (or,
	// if there is none yet, against an empty baseline, which ZScore's own
	// minSamplesForZScore floor already treats as "not enough signal to
	// judge" rather than a degenerate mean-0 stand-in).
	var zDiversity, zDeny, zDenyBlock, zToolCalls float64
	if st.prev.toolCalls >= d.cfg.MLScore.MinCalls {
		zDiversity = zCount(&st.mlStats.diversity, diversity)
		zDeny = st.mlStats.denyRatio.ZScore(denyRatio)
		// deny_ratio's block-gating z-score additionally floors the effective
		// stddev at this window's own binomial standard error,
		// sqrt(pSmoothed*(1-pSmoothed)/toolCalls) -- a ratio's sampling noise
		// depends on how many real tool calls it was computed from, and the
		// existing floors (calibrated from the baseline's typical window size)
		// have no way to know this window's toolCalls is far smaller. This is
		// separate from zDeny (used for the ml_score log record and the
		// anomalous/fold-conditionally decision) so a small, noisy window still
		// gets logged as telemetry -- it just can't gate an auto-block. Below
		// MinCalls real tool calls specifically (as distinct from the existing
		// MinCalls gate on total, which passthrough traffic inflates without
		// adding a single tool call), there's no reliable signal at all: treated
		// as 0 -- which since round 12 is what the enclosing gate does for all
		// three of these features, not just this one.
		//
		// pSmoothed is a continuity-corrected estimate of the baseline mean,
		// used only for this SE computation (never for the z-score's numerator,
		// which stays the true historical mean p): at p=0 (an identity that has
		// never once been denied), the raw formula sqrt(0*(1-0)/n) is 0, and
		// combined with the relative floor (also 0 at mean 0) the effective
		// stddev collapses to 0, leaving this feature permanently blind to a
		// first deny spike no matter how severe. The correction adds half an
		// imaginary deny to a small, FIXED number of pseudo-observations,
		// denyRatioContinuityWeight (the standard continuity correction for a
		// proportion near a boundary) -- deliberately NOT this window's own
		// toolCalls (round 9's choice) and NOT the baseline's accumulated fold
		// count (round 7's original).
		//
		// The fold count was wrong because it grows unboundedly over an
		// identity's lifetime, making the invented SE shrink without bound as
		// clean history piled up: a single ordinary denial after ~159 clean
		// windows scored z=4.01 (blocked), and after 500 windows z=7.08, purely
		// from having run cleanly longer (fixed in round 8).
		//
		// toolCalls was wrong for a subtler reason (round 11): at a spotless
		// baseline (p=0) it made pSmoothed itself decay as ~0.5/n, so the
		// resulting se carried a 1/n factor -- which canceled exactly against
		// denyRatio's own 1/n, collapsing this "binomial standard error" into a
		// bare linear function of the raw denial count, independent of window
		// size. The same fixed 3 habitual denials scored z=4.40 in a 20-call
		// window and z=4.25 in a 500-call one, both past the shipped example
		// config's 4.0 block threshold: an operator newly denying one tool
		// auto-blocked an agent at a 0.6% deny rate, and because round 9's
		// blockScore promotion marks that window anomalous, the baseline never
		// folded and the block re-fired forever. A proper proportion test's SE
		// must shrink as 1/sqrt(n) as the sample grows -- the same fixed
		// absolute count matters less in a larger sample -- and decoupling the
		// correction's weight from n restores exactly that (2.93 at n=20, 0.59
		// at n=500; a real 50%-deny window at n=20 still scores 9.76).
		//
		// A fixed weight also makes round 8's concern impossible by
		// construction: the correction no longer depends on any accumulating
		// counter at all, window-based or baseline-based.
		p := st.mlStats.denyRatio.mean
		n := float64(st.prev.toolCalls)
		pSmoothed := (p*denyRatioContinuityWeight + 0.5) / (denyRatioContinuityWeight + 1)
		se := math.Sqrt(pSmoothed * (1 - pSmoothed) / n)
		zDenyBlock = st.mlStats.denyRatio.ZScoreFloored(denyRatio, se)
		// zToolCalls exists solely to gate deny_ratio's block candidacy on
		// whether deny_ratio's own denominator declined -- see mlFeatureState's
		// doc comment in identity_state.go for why zRate (scored from total,
		// deliberately inclusive of protocol passthrough) cannot stand in for
		// this. Never scored as its own ml_score feature or logged.
		zToolCalls = st.mlStats.toolCalls.ZScore(n)
	}
	zInterArrival := st.mlStats.interArrival.ZScore(interArrival)

	score, feature := maxAbsZ(zRate, zDiversity, zDeny, zInterArrival)
	blockScore, blockFeature := maxHarmfulZ(zRate, zDiversity, zDenyBlock, zToolCalls, zInterArrival)
	// blockScore can exceed score only in the one case where zDeny's own
	// divisor degenerates (a p=0, zero-variance deny_ratio baseline, whose
	// continuity-corrected block-gating variant is deliberately more
	// sensitive -- see zDenyBlock's doc comment above). Without this, a
	// block in that case would fire with no corresponding ml_score log
	// record at all, breaking the invariant auto_block.score_threshold's
	// own validation message promises: every Block() is accompanied by a
	// logged anomaly explaining it.
	if blockScore > score {
		score, feature = blockScore, blockFeature
	}
	anomalous := score > d.cfg.MLScore.ScoreThreshold

	// ponytail: only fold a window's raw values into the baseline when the
	// window itself wasn't flagged anomalous. Folding a flagged window in
	// unconditionally (the old behavior) drags the baseline's variance wide
	// enough that an identical repeat of the same attack stops scoring as
	// anomalous after round one -- verified: 4 identical bursts, only the
	// first got flagged. Trade-off: a legitimate *permanent* traffic-shape
	// change now keeps flagging (and, under auto_block, keeps getting
	// blocked) until the operator raises score_threshold -- the safer
	// failure direction, since the alternative is silently desensitizing on
	// what might be real attack traffic.
	//
	// The inner gate mirrors the scoring one above exactly: a window with no
	// real tool calls is not evidence about tool diversity, deny ratio or
	// tool-call volume, so it must not join those three baselines either --
	// scoring a tool-call-free window as 0 while still folding it would leave
	// the mean-0 poisoning fully intact.
	if !anomalous {
		st.mlStats.rate.Update(rate)
		st.mlStats.interArrival.Update(interArrival)
		if st.prev.toolCalls >= d.cfg.MLScore.MinCalls {
			st.mlStats.diversity.Update(diversity)
			st.mlStats.denyRatio.Update(denyRatio)
			st.mlStats.toolCalls.Update(float64(st.prev.toolCalls))
		}
	}

	// autoBlockSeconds stays 0 unless THIS anomaly is the one that actually
	// triggers a live Block() call below -- never a guess about what a
	// block *would* last had auto_block been enabled/threshold different.
	var autoBlockSeconds int
	if d.cfg.AutoBlock.Enabled && d.blocker != nil && blockScore > d.cfg.AutoBlock.ScoreThreshold {
		d.blocker.Block(e.Identity, e.Tenant, fmt.Sprintf(
			"ml_score %.2f (feature: %s) exceeded auto-block threshold %.2f",
			blockScore, blockFeature, d.cfg.AutoBlock.ScoreThreshold))
		autoBlockSeconds = d.cfg.AutoBlock.BlockDurationSeconds
	}

	if !anomalous {
		return domain.Anomaly{}, false
	}
	if st.flaggedThisWindow[domain.KindMLScore] {
		return domain.Anomaly{}, false
	}
	if st.flaggedThisWindow == nil {
		st.flaggedThisWindow = make(map[domain.Kind]bool)
	}
	st.flaggedThisWindow[domain.KindMLScore] = true
	return domain.Anomaly{
		Timestamp: d.now(),
		Identity:  e.Identity,
		Tenant:    e.Tenant,
		Kind:      domain.KindMLScore,
		Detail: fmt.Sprintf(
			"combined z-score %.2f (driving feature: %s) exceeded threshold %.2f",
			score, feature, d.cfg.MLScore.ScoreThreshold),
		Entry:            e,
		Score:            &score,
		AutoBlockSeconds: autoBlockSeconds,
	}, true
}

// maxAbsZ returns the largest-magnitude of the four feature z-scores and
// the name of the feature that produced it, for ml_score's combined
// score and its human-readable Detail.
func maxAbsZ(zRate, zDiversity, zDeny, zInterArrival float64) (float64, string) {
	best := math.Abs(zRate)
	feature := "call_rate"
	if v := math.Abs(zDiversity); v > best {
		best, feature = v, "tool_diversity"
	}
	if v := math.Abs(zDeny); v > best {
		best, feature = v, "deny_ratio"
	}
	if v := math.Abs(zInterArrival); v > best {
		best, feature = v, "inter_arrival_time"
	}
	return best, feature
}

// maxHarmfulZ scores only the direction each feature actually signals
// risk in -- more calls, more tool diversity, and more denials are all
// "positive z is worse"; faster calls (shorter inter-arrival spacing) is
// "negative z is worse", so its sign is flipped before comparing. A
// decline in any of these (quieter traffic, fewer denials, less
// diversity, slower calls) is not a threat signal auto-block exists to
// catch -- maxAbsZ (used for the ml_score log record) still surfaces it
// for visibility, but it must never gate a Block call. zDenyBlock is
// deny_ratio's block-gating variant (see checkMLScore's comment above
// it), not the raw zDeny used for logging.
//
// Both the deny_ratio and inter_arrival_time candidates are additionally
// gated on volume not having declined, because both are quantities a
// shrinking window inflates on its own. deny_ratio, like tool_diversity
// before round 5's raw-count fix, is a ratio -- and a ratio rises when call
// volume declines over an unchanged absolute numerator (round 7: an identity
// with a handful of habitual denied probes scores as increasingly anomalous
// purely because a quiet window shrank the denominator, no denial behavior
// having actually changed; unlike diversity, deny_ratio can't simply switch
// to a raw count without losing the ability to detect a genuine
// small-absolute-count proportional spike, so it's gated on volume instead.
// A binomial-SE floor alone cannot close this: the SE shrinks as 1/sqrt(n)
// while the artifact grows as 1/n). Calls arriving closer together is
// likewise only a threat signal paired with volume at or above baseline (an
// actual burst); a client that simply made fewer calls that happened to land
// closer together, or had a naturally low but proportionally high deny count
// in a quiet window, is not one.
//
// The two use *different* volume gates, because they have different
// denominators. inter_arrival_time is gated on zRate >= 0:
// its delta count is total-1 within a window, the same quantity zRate
// measures, so a decline in zRate is a valid proxy for "this window's
// inter-arrival sample shrank." deny_ratio is gated on
// zToolCalls >= 0 -- its own denominator is toolCalls,
// not total (round 9: zRate can hold steady or rise via protocol passthrough
// or tool-less error traffic while toolCalls itself collapses, which
// re-opened the exact ratio-volume-decline artifact round 7's zRate-based
// gate was built to close, since padding total satisfies that gate without
// protecting the denominator it actually needs to protect). See
// volumeDeclineMargin's own doc comment for why both gates compare against
// a small negative margin, not a bare zero.
//
// The trade-off in both cases: a genuine attack at conspicuously low volume
// no longer auto-blocks either -- still logged via the unaffected two-sided
// score, matching this feature's established posture (see round 4's accepted
// "quiet slow-drip exfil unblockable" trade-off) of preferring a missed block
// over a false one.
//
// The result is floored at 0: if every feature moved in the benign
// direction, there is no case for blocking at all, not a large negative
// "score."
// volumeDeclineMargin is how far below zero zToolCalls/zRate must fall
// before the volume-decline gates in maxHarmfulZ below treat that as
// real evidence of a decline, rather than a bare "which side of zero"
// sign check.
//
// A bare `>= 0` gate on a z-score is a hard cutoff with no hysteresis:
// when the gated feature's true value sits within its own baseline's
// noise band of the mean -- exactly the case for an attack that doesn't
// itself change call volume, e.g. a deny-rate spike at an unchanged
// call count -- its z-score's SIGN is effectively a coin flip driven by
// which way that noise happened to land, not by anything about the
// attack. Direct instrumentation of TestRecallBenchmark_DenyRateSpike
// confirmed exactly this: a severe, correctly-scored deny_ratio
// candidate (blockScore z=9.57, far past the shipped example's 8.0
// auto_block threshold) was excluded from blockScore whenever
// zToolCalls's noise-driven sign happened to be negative, and admitted
// whenever it happened to be positive -- identical attack severity,
// coin-flip outcome, purely from an unrelated feature's sampling noise
// (the benchmark's own "40% deny ratio: 12/20 auto-blocked" result was
// this coin flip, not a real signal about deny-rate severity).
//
// A one-sigma margin is the standard fix for a gate that flaps under
// noise right at its own crossing point (hysteresis): require the
// gated feature to be at least this many standard deviations below its
// baseline before treating it as evidence of an actual decline, rather
// than treating any negative point estimate as one. 1.0 is deliberately
// modest -- this gate exists to protect against a genuine volume-decline
// artifact inflating deny_ratio/inter_arrival_time (see checkMLScore's
// own comment on why those two need this gate at all), not to make the
// gate hard to trip: a real decline clears 1 sigma quickly, while noise
// within 1 sigma of the mean -- exactly zToolCalls/zRate's own
// definition of "ordinary" -- no longer silently vetoes a real, severe
// anomaly on a different feature.
const volumeDeclineMargin = 1.0

func maxHarmfulZ(zRate, zDiversity, zDenyBlock, zToolCalls, zInterArrival float64) (float64, string) {
	best := zRate
	feature := "call_rate"
	if v := zDiversity; v > best {
		best, feature = v, "tool_diversity"
	}
	if zToolCalls >= -volumeDeclineMargin {
		if v := zDenyBlock; v > best {
			best, feature = v, "deny_ratio"
		}
	}
	if zRate >= -volumeDeclineMargin {
		if v := -zInterArrival; v > best {
			best, feature = v, "inter_arrival_time"
		}
	}
	if best < 0 {
		best = 0
	}
	return best, feature
}

func (d *Detector) emit(a domain.Anomaly) {
	if err := d.writer.Write(a); err != nil && d.onError != nil {
		d.onError(err)
	}
	if d.buffer != nil {
		d.buffer.Add(a)
	}
}
