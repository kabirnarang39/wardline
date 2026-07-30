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

	zRate := st.mlStats.rate.ZScore(rate)
	zDiversity := st.mlStats.diversity.ZScore(diversity)
	zDeny := st.mlStats.denyRatio.ZScore(denyRatio)
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
	// as 0.
	//
	// pSmoothed is a continuity-corrected estimate of the baseline mean,
	// used only for this SE computation (never for the z-score's numerator,
	// which stays the true historical mean p): at p=0 (an identity that has
	// never once been denied), the raw formula sqrt(0*(1-0)/n) is 0, and
	// combined with the relative floor (also 0 at mean 0) the effective
	// stddev collapses to 0, leaving this feature permanently blind to a
	// first deny spike no matter how severe. The correction treats this
	// window's own toolCalls as pseudo-observations plus half an imaginary
	// deny (the standard continuity correction for a proportion near a
	// boundary), deliberately keyed to *this window's* sample size rather
	// than the baseline's accumulated fold count: an earlier version of this
	// fix used mlStats.denyRatio.count here, which grows unboundedly over an
	// identity's lifetime and made the invented SE shrink without bound as
	// clean history piled up -- a single ordinary denial after ~159 clean
	// windows scored z=4.01 (blocked), and after 500 windows z=7.08, purely
	// from having run cleanly longer, not from anything about the denial
	// itself. toolCalls is naturally bounded to realistic per-window call
	// volumes and carries no such drift.
	var zDenyBlock float64
	if st.prev.toolCalls >= d.cfg.MLScore.MinCalls {
		p := st.mlStats.denyRatio.mean
		n := float64(st.prev.toolCalls)
		pSmoothed := (p*n + 0.5) / (n + 1)
		se := math.Sqrt(pSmoothed * (1 - pSmoothed) / n)
		zDenyBlock = st.mlStats.denyRatio.ZScoreFloored(denyRatio, se)
	}
	zInterArrival := st.mlStats.interArrival.ZScore(interArrival)
	// zToolCalls exists solely to gate deny_ratio's block candidacy on
	// whether deny_ratio's own denominator declined -- see mlFeatureState's
	// doc comment in identity_state.go for why zRate (scored from total,
	// deliberately inclusive of protocol passthrough) cannot stand in for
	// this. Never scored as its own ml_score feature or logged.
	zToolCalls := st.mlStats.toolCalls.ZScore(float64(st.prev.toolCalls))

	score, feature := maxAbsZ(zRate, zDiversity, zDeny, zInterArrival)
	blockScore, blockFeature := maxHarmfulZ(zRate, zDiversity, zDenyBlock, zToolCalls, zInterArrival)
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
		st.mlStats.toolCalls.Update(float64(st.prev.toolCalls))
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
// denominators. inter_arrival_time is gated on zRate >= 0: its delta count is
// total-1 within a window, the same quantity zRate measures, so a decline in
// zRate is a valid proxy for "this window's inter-arrival sample shrank."
// deny_ratio is gated on zToolCalls >= 0 -- its own denominator is toolCalls,
// not total (round 9: zRate can hold steady or rise via protocol passthrough
// or tool-less error traffic while toolCalls itself collapses, which
// re-opened the exact ratio-volume-decline artifact round 7's zRate-based
// gate was built to close, since padding total satisfies that gate without
// protecting the denominator it actually needs to protect).
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
func maxHarmfulZ(zRate, zDiversity, zDenyBlock, zToolCalls, zInterArrival float64) (float64, string) {
	best := zRate
	feature := "call_rate"
	if v := zDiversity; v > best {
		best, feature = v, "tool_diversity"
	}
	if zToolCalls >= 0 {
		if v := zDenyBlock; v > best {
			best, feature = v, "deny_ratio"
		}
	}
	if zRate >= 0 {
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
