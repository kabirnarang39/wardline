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
// here beyond a nil check.
type blocker interface {
	Block(identity, reason string)
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

	mu    sync.Mutex
	state map[string]*identityState
}

func NewDetector(cfg domain.HeuristicConfig, writer domain.Writer, buffer alertSink, blocker blocker, onError func(error), now func() time.Time) *Detector {
	return &Detector{
		cfg:     cfg,
		writer:  writer,
		buffer:  buffer,
		blocker: blocker,
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
	st, ok := d.state[e.Identity]
	if !ok {
		st = &identityState{tools: make(map[string]struct{}), windowStart: now}
		d.state[e.Identity] = st
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
		if a, ok := d.checkMLScore(e, st); ok {
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
		Kind:      domain.KindDenyRateSpike,
		Detail:    "deny ratio exceeded threshold within the trailing window",
		Entry:     e,
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
	rate := float64(st.prev.total)
	var diversity float64
	if st.prev.total > 0 {
		diversity = float64(len(st.prev.uniqueTools)) / float64(st.prev.total)
	}
	var denyRatio float64
	if st.prev.toolCalls > 0 {
		denyRatio = float64(st.prev.deny) / float64(st.prev.toolCalls)
	}
	var interArrival float64
	if st.prev.interArrivalN > 0 {
		interArrival = st.prev.interArrivalSum.Seconds() / float64(st.prev.interArrivalN)
	}

	zRate := st.mlStats.rate.ZScore(rate)
	zDiversity := st.mlStats.diversity.ZScore(diversity)
	zDeny := st.mlStats.denyRatio.ZScore(denyRatio)
	zInterArrival := st.mlStats.interArrival.ZScore(interArrival)

	score, feature := maxAbsZ(zRate, zDiversity, zDeny, zInterArrival)
	blockScore, blockFeature := maxHarmfulZ(zRate, zDiversity, zDeny, zInterArrival)
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
	if !anomalous {
		st.mlStats.rate.Update(rate)
		st.mlStats.diversity.Update(diversity)
		st.mlStats.denyRatio.Update(denyRatio)
		st.mlStats.interArrival.Update(interArrival)
	}

	if d.cfg.AutoBlock.Enabled && d.blocker != nil && blockScore > d.cfg.AutoBlock.ScoreThreshold {
		d.blocker.Block(e.Identity, fmt.Sprintf(
			"ml_score %.2f (feature: %s) exceeded auto-block threshold %.2f",
			blockScore, blockFeature, d.cfg.AutoBlock.ScoreThreshold))
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
		Kind:      domain.KindMLScore,
		Detail: fmt.Sprintf(
			"combined z-score %.2f (driving feature: %s) exceeded threshold %.2f",
			score, feature, d.cfg.MLScore.ScoreThreshold),
		Entry: e,
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
// for visibility, but it must never gate a Block call. The result is
// floored at 0: if every feature moved in the benign direction, there is
// no case for blocking at all, not a large negative "score."
func maxHarmfulZ(zRate, zDiversity, zDeny, zInterArrival float64) (float64, string) {
	best := zRate
	feature := "call_rate"
	if v := zDiversity; v > best {
		best, feature = v, "tool_diversity"
	}
	if v := zDeny; v > best {
		best, feature = v, "deny_ratio"
	}
	if v := -zInterArrival; v > best {
		best, feature = v, "inter_arrival_time"
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
