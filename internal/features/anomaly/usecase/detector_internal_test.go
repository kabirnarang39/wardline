package usecase

// These tests live in package usecase (not usecase_test like the rest of
// detector_test.go) because they assert on Detector's unexported
// per-identity state directly: "a sub-floor window folds nothing into the
// baseline" and "a blocked identity's rejection traffic leaves window
// state untouched" are both claims about internal state that no
// externally-observable output distinguishes from a coincidence.

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type nopWriter struct {
	anomalies []domain.Anomaly
}

func (w *nopWriter) Write(a domain.Anomaly) error {
	w.anomalies = append(w.anomalies, a)
	return nil
}

type blockRecorder struct {
	calls []string
}

func (b *blockRecorder) Block(tenantName, identity, reason string) {
	b.calls = append(b.calls, identity+": "+reason)
}

type internalClock struct {
	t time.Time
}

func (c *internalClock) now() time.Time { return c.t }

// feedWindow publishes n allow-decision calls spaced by spacing, cycling
// through tools -- the internal-package twin of detector_test.go's
// publishWindow.
func feedWindow(d *Detector, clock *internalClock, identity string, tools []string, n int, spacing time.Duration) {
	for i := 0; i < n; i++ {
		d.Publish(auditdomain.Entry{Identity: identity, Tool: tools[i%len(tools)], Decision: "allow"})
		clock.t = clock.t.Add(spacing)
	}
}

func distinctTools(n int) []string {
	tools := make([]string, n)
	for i := range tools {
		tools[i] = fmt.Sprintf("tool_%d", i)
	}
	return tools
}

// baselineSampleCounts is the one thing "did this window get folded into
// the baseline?" is observable through. toolCalls belongs here for the same
// reason the other four do, and is not optional just because it is never
// scored as an ml_score feature in its own right.
//
// Since round 12 the five split into two fold groups, and capturing all five
// together is what makes the split itself assertable:
//
//   - rate and interArrival fold whenever the scored window was not
//     anomalous. Both are volumetric over *all* of a window's traffic
//     (rate reads windowCounts.total; interArrival's delta count is
//     total-1), so protocol passthrough and tool-less error entries are
//     legitimate evidence for them.
//   - diversity, denyRatio and toolCalls additionally require
//     st.prev.toolCalls >= MLScore.MinCalls. A window with no real tool
//     calls carries no information about tool-call behavior at all, and
//     folding one pinned these three baselines at mean 0 -- see
//     TestDetector_MLScore_ToolCallFreeWindows_DoNotPoisonBaselines.
//
// So a change that moved, duplicated or mis-grouped any one of the five
// Update calls desyncs its count from its group -- and until all five were
// captured here nothing ever read them back, so no test could have noticed.
type baselineSampleCounts struct {
	rate, diversity, denyRatio, interArrival, toolCalls int64
}

func sampleCounts(st *identityState) baselineSampleCounts {
	return baselineSampleCounts{
		rate:         st.mlStats.rate.count,
		diversity:    st.mlStats.diversity.count,
		denyRatio:    st.mlStats.denyRatio.count,
		interArrival: st.mlStats.interArrival.count,
		toolCalls:    st.mlStats.toolCalls.count,
	}
}

// mlFloorCfg is the shipped example config's shape, scaled down to a 60s
// window: log at 3.0, block at 4.0, and refuse to score any window with
// fewer than 5 calls.
func mlFloorCfg() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore:       domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0, MinCalls: 5},
		AutoBlock:     domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 4.0, BlockDurationSeconds: 300},
	}
}

// TestDetector_MLScore_MinCallsFloor_SkipsSingleCallWindow is the
// regression gate for N2: without MinCalls, a window containing exactly
// one call scores as a wild outlier by construction, not by behavior.
// Against the baseline this test builds ({10, 11} alternating, mean 10.5,
// sample stddev 0.5270, floored by zCount to
// max(0.15*10.5 = 1.575, sqrt(10.5) = 3.2404) = 3.2404), a 1-call window
// scores z_rate = (1 - 10.5) / 3.2404 = -2.93 -- and scored -6.03 against
// the relative floor alone, past both the 3.0 log threshold and the 4.0
// block threshold. Either way the floors are not what saves this case, which
// is the point of the MinCalls gate. An identity that simply went
// quiet for one window would be auto-blocked. With the floor, the window
// is skipped outright: no anomaly, nothing folded, no Block call.
func TestDetector_MLScore_MinCallsFloor_SkipsSingleCallWindow(t *testing.T) {
	clock := &internalClock{t: time.Unix(0, 0)}
	writer := &nopWriter{}
	blocker := &blockRecorder{}
	d := NewDetector(mlFloorCfg(), writer, nil, blocker, nil, clock.now)

	// 10 baseline windows alternating 10 and 11 calls, one distinct tool
	// per call at a fixed 1s spacing. Deny ratio is a constant 0 and mean
	// inter-arrival a constant 1s, so those two have zero variance and
	// score 0. Diversity is not constant: distinctTools(n) gives n calls n
	// distinct names, so the raw distinct-tool count tracks the call count
	// exactly (10/11) and has the same mean, variance and z as rate at
	// every step -- it simply never overtakes rate, which maxAbsZ compares
	// first and only replaces on a strict >. A window is scored and folded
	// by the first call of the *following* window, so 10 published windows
	// leaves 9 folded here.
	for i := 0; i < 10; i++ {
		n := 10 + i%2
		feedWindow(d, clock, "alice", distinctTools(n), n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	// The whole of the next window is a single call -- this call's own
	// rollover scores and folds baseline window 10 (total >= 5, so the
	// floor doesn't touch it), bringing every baseline to 10 samples.
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	st := d.state[tenantIdentityKey("", "alice")]
	before := sampleCounts(st)
	if before.rate != 10 {
		t.Fatalf("test setup: expected 10 folded baseline samples before the 1-call window, got %+v", before)
	}

	// Roll over again: this is the call that scores the 1-call window.
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if after := sampleCounts(d.state[tenantIdentityKey("", "alice")]); after != before {
		t.Errorf("a sub-MinCalls window must not be folded into any baseline\nbefore: %+v\nafter:  %+v", before, after)
	}
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected no ml_score anomaly for a 1-call window under the MinCalls floor, got %+v", writer.anomalies)
		}
	}
	if len(blocker.calls) != 0 {
		t.Errorf("expected zero Block calls for a 1-call window under the MinCalls floor, got %+v", blocker.calls)
	}
}

// feedMixedWindow publishes n calls, the first denyCount of them recorded as
// policy denials, each with its own distinct tool name -- the
// internal-package twin of detector_test.go's publishMixedWindow.
func feedMixedWindow(d *Detector, clock *internalClock, identity string, n, denyCount int, spacing time.Duration) {
	for i := 0; i < n; i++ {
		decision := "allow"
		if i < denyCount {
			decision = "deny"
		}
		d.Publish(auditdomain.Entry{Identity: identity, Tool: fmt.Sprintf("tool_%d", i), Decision: decision})
		clock.t = clock.t.Add(spacing)
	}
}

// TestDetector_MLScore_DenyRatioFixedSmallCount_NeverBlocksRegardlessOfVolume
// is the regression gate for round 11: deny_ratio's block-gating standard
// error used to weight its continuity correction by the scored window's own
// toolCalls, which at a spotless baseline (p=0) made pSmoothed decay as
// ~0.5/n and so gave se its own 1/n factor -- one that canceled exactly
// against the deny ratio's 1/n, collapsing a "binomial standard error" into
// a bare linear function of the raw denial count. The same fixed 3 habitual
// denials scored z=4.40 in a 20-call window and z=4.25 in a 500-call one,
// both past the 4.0 block threshold: an operator who tightens policy to deny
// one previously-allowed tool auto-blocks a 500-call/window agent at a 0.6%
// deny rate, something the shipped deny_rate_spike heuristic would not even
// log below a 50% ratio.
//
// This test asserts the property, not one magic number: the *same* absolute
// denial count at two volumes 25x apart must not block, and the larger
// window must score conspicuously lower than the smaller one (a fixed
// absolute count is less significant in a bigger sample -- the 1/sqrt(n) law
// the toolCalls-weighted form broke). Weighting by the fixed
// denyRatioContinuityWeight (8) gives pSmoothed = 0.5/9 = 0.0555556 in both cases
// and se = sqrt(0.0555556*0.9444444/n):
//
//	toolCalls | ratio | se        | zDenyBlock
//	20        | 0.15  | 0.0512197 | 2.9286
//	500       | 0.006 | 0.0102439 | 0.5857
//
// The second half of the failure is what made it permanent rather than
// self-correcting: round 9's blockScore-into-score promotion (kept, and
// still correct for the missing-log-record invariant it protects) marked
// such a window anomalous, and an anomalous window is never folded into the
// baseline, so p stayed pinned at exactly 0 and every later window carrying
// the same habitual denials re-blocked. The reviewer measured 10 consecutive
// windows of 3 denials producing 10 Block calls with the baseline mean still
// 0.000000. Both halves are asserted below: no block, and the baseline
// actually folds the window afterwards.
func TestDetector_MLScore_DenyRatioFixedSmallCount_NeverBlocksRegardlessOfVolume(t *testing.T) {
	// Volume is held identical between baseline and scored window in every
	// case, so call_rate, tool_diversity, toolCalls and inter-arrival all
	// score exactly 0 and deny_ratio is the only feature that moved -- which
	// also keeps the zToolCalls >= 0 gate open, so deny_ratio really is a
	// live auto-block candidate rather than being excluded for an unrelated
	// reason.
	for _, tc := range []struct {
		toolCalls int
		spacing   time.Duration
	}{
		{toolCalls: 20, spacing: time.Second},
		{toolCalls: 500, spacing: 100 * time.Millisecond},
	} {
		t.Run(fmt.Sprintf("%d tool calls", tc.toolCalls), func(t *testing.T) {
			clock := &internalClock{t: time.Unix(0, 0)}
			blocker := &blockRecorder{}
			d := NewDetector(mlFloorCfg(), &nopWriter{}, nil, blocker, nil, clock.now)

			// 11 spotless windows: deny_ratio's baseline is mean 0 with zero
			// variance, the shape whose degenerate SE this test is about.
			for i := 0; i < 11; i++ {
				feedMixedWindow(d, clock, "alice", tc.toolCalls, 0, tc.spacing)
				clock.t = clock.t.Add(61 * time.Second)
			}

			// The 3 denials. This window's own first call folds baseline window
			// 11, so `before` is the 11-sample baseline the window is scored
			// against.
			feedMixedWindow(d, clock, "alice", tc.toolCalls, 3, tc.spacing)
			before := sampleCounts(d.state[tenantIdentityKey("", "alice")])
			if before.denyRatio != 11 {
				t.Fatalf("test setup: expected 11 folded deny-ratio samples, got %+v", before)
			}
			if mean := d.state[tenantIdentityKey("", "alice")].mlStats.denyRatio.mean; mean != 0 {
				t.Fatalf("test setup: expected a spotless deny-ratio baseline (mean 0), got %v", mean)
			}

			clock.t = clock.t.Add(61 * time.Second)
			d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

			if len(blocker.calls) != 0 {
				t.Errorf("3 denials in a %d-call window must never auto-block against a spotless baseline, got %+v", tc.toolCalls, blocker.calls)
			}
			// The permanent-lockout half: the window was not treated as
			// anomalous, so it folded and the baseline learned from it. Without
			// this, a future regression that merely lowered the score below the
			// block threshold while still flagging the window would leave the
			// baseline pinned at mean 0 forever.
			after := sampleCounts(d.state[tenantIdentityKey("", "alice")])
			if after.denyRatio != before.denyRatio+1 {
				t.Errorf("a non-anomalous deny window must fold into the baseline (else p stays pinned at 0 forever)\nbefore: %+v\nafter:  %+v", before, after)
			}
			if mean := d.state[tenantIdentityKey("", "alice")].mlStats.denyRatio.mean; mean <= 0 {
				t.Errorf("expected the folded window to move the deny-ratio baseline mean off 0, got %v", mean)
			}
		})
	}

	// The reviewer's exact repro of the lockout: 10 consecutive windows
	// carrying the same 3 habitual denials produced 10 Block calls, with the
	// baseline mean still exactly 0 after all 10.
	t.Run("ten consecutive windows of the same 3 denials", func(t *testing.T) {
		clock := &internalClock{t: time.Unix(0, 0)}
		blocker := &blockRecorder{}
		d := NewDetector(mlFloorCfg(), &nopWriter{}, nil, blocker, nil, clock.now)

		for i := 0; i < 11; i++ {
			feedMixedWindow(d, clock, "alice", 200, 0, 200*time.Millisecond)
			clock.t = clock.t.Add(61 * time.Second)
		}
		for i := 0; i < 10; i++ {
			feedMixedWindow(d, clock, "alice", 200, 3, 200*time.Millisecond)
			clock.t = clock.t.Add(61 * time.Second)
		}
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

		if len(blocker.calls) != 0 {
			t.Errorf("an unchanged habitual denial count must never auto-block, however many windows it repeats for, got %d: %+v", len(blocker.calls), blocker.calls)
		}
		if mean := d.state[tenantIdentityKey("", "alice")].mlStats.denyRatio.mean; mean <= 0 {
			t.Errorf("expected the deny-ratio baseline to have learned the habitual denials rather than staying pinned at 0, got %v", mean)
		}
	})
}

// feedPassthroughWindow publishes n MCP protocol-lifecycle passthrough
// entries spaced by spacing -- the internal-package twin of the padding
// loop in detector_test.go's ToolCallShareCollapse test. Every one lands in
// windowCounts.total (so a window of them alone clears the total-based
// MinCalls gate) and none of them reaches toolCalls, uniqueTools or deny,
// because isToolCall rejects decision "passthrough" outright.
func feedPassthroughWindow(d *Detector, clock *internalClock, identity string, n int, spacing time.Duration) {
	for i := 0; i < n; i++ {
		d.Publish(auditdomain.Entry{Identity: identity, Tool: "tools/list", Decision: "passthrough"})
		clock.t = clock.t.Add(spacing)
	}
}

// TestDetector_MLScore_ToolCallFreeWindows_DoNotPoisonBaselines is the
// regression gate for round 12. checkMLScore's MinCalls gate reads
// st.prev.total, which counts protocol-lifecycle passthrough and tool-less
// error entries (see isToolCall's doc comment) -- so a window with *zero*
// real tool calls clears it. Before round 12, tool_diversity, deny_ratio and
// toolCalls were scored and folded from such windows anyway, pinning all
// three baselines at mean 0 with zero variance: a baseline carrying no
// information whatsoever about tool-call behavior, the exact class MinCalls
// exists to exclude, just measured against the wrong denominator.
//
// The consequence was a permanent lockout. Hand-traced against the
// pre-round-12 code, the first legitimate window after 12 passthrough-only
// ones -- 6 calls over 5 distinct tools, ordinary volume, ordinary spacing,
// zero denials -- scored
// zDiversity = (5 - 0) / max(1.0, sqrt(0)) = 5.00, past both the 3.0 log
// threshold and the 4.0 block threshold; and because 5.00 > 3.0 marks the
// window anomalous, it was never folded, so the baseline stayed at mean 0
// and every following legitimate window blocked again (the reviewer measured
// 6 consecutive windows producing 6 Block calls). Reachable by any client
// that only ever calls tools/list -- an inspector, a capability-discovery
// bot, a health-check probe -- or by a reconnect loop, or by a client whose
// every request currently fails to parse.
//
// The assertions below are on the split-fold behavior itself, not just on
// the safe outcome: {diversity, denyRatio, toolCalls} must stay at zero
// samples through the passthrough-only windows while {rate, interArrival}
// keep accumulating, and must then start accumulating once real tool-call
// windows arrive.
func TestDetector_MLScore_ToolCallFreeWindows_DoNotPoisonBaselines(t *testing.T) {
	clock := &internalClock{t: time.Unix(0, 0)}
	writer := &nopWriter{}
	blocker := &blockRecorder{}
	d := NewDetector(mlFloorCfg(), writer, nil, blocker, nil, clock.now)

	// 12 windows of 6 tools/list entries each: total = 6 clears MinCalls
	// (5), toolCalls is 0 throughout. A window is scored and folded by the
	// first call of the *following* window, so 12 published windows leaves
	// 11 scored here.
	for i := 0; i < 12; i++ {
		feedPassthroughWindow(d, clock, "alice", 6, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	afterPassthrough := sampleCounts(d.state[tenantIdentityKey("", "alice")])
	want := baselineSampleCounts{rate: 11, interArrival: 11}
	if afterPassthrough != want {
		t.Fatalf("tool-call-free windows must fold into rate/interArrival only, leaving diversity/denyRatio/toolCalls empty\nwant: %+v\ngot:  %+v", want, afterPassthrough)
	}

	// The first legitimate window: 6 calls (identical volume and spacing to
	// the passthrough windows, so zRate and zInterArrival are both 0) spread
	// over 5 distinct tools. Its own first call rolls over and folds
	// passthrough window 12, taking rate/interArrival to 12 samples while the
	// other three stay at 0.
	feedWindow(d, clock, "alice", distinctTools(5), 6, time.Second)
	if got := sampleCounts(d.state[tenantIdentityKey("", "alice")]); got != (baselineSampleCounts{rate: 12, interArrival: 12}) {
		t.Fatalf("the last passthrough window must still fold into rate/interArrival only, got %+v", got)
	}

	// Roll over: this is the call that scores the legitimate window.
	// zDiversity is 0 -- not because of any new special case, but because
	// ZScore's own count < minSamplesForZScore guard sees an empty baseline
	// and reports "not enough signal to judge" instead of dividing by a
	// degenerate mean-0 stand-in.
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "tool_0", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("an ordinary 6-call/5-tool window following tool-call-free traffic must never auto-block, got %+v", blocker.calls)
	}
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected no ml_score anomaly at all in this run, got %+v", writer.anomalies)
		}
	}
	// The window was not anomalous, so it folded -- and this time all five
	// baselines advance, because toolCalls (6) clears MinCalls (5). This is
	// the other half of the fix: a real tool-call window is exactly what
	// these three baselines are supposed to learn from.
	if got := sampleCounts(d.state[tenantIdentityKey("", "alice")]); got != (baselineSampleCounts{rate: 13, diversity: 1, denyRatio: 1, interArrival: 13, toolCalls: 1}) {
		t.Fatalf("a window with real tool calls must fold into all five baselines, got %+v", got)
	}

	// And it keeps working: 9 more identical legitimate windows carry
	// diversity's baseline past minSamplesForZScore (8) without ever
	// producing an anomaly or a block, so the recovery path is real and not
	// just "the first one happened to be unscoreable".
	for i := 0; i < 9; i++ {
		clock.t = clock.t.Add(61 * time.Second)
		feedWindow(d, clock, "alice", distinctTools(5), 6, time.Second)
	}
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "tool_0", Decision: "allow"})

	if got := d.state[tenantIdentityKey("", "alice")].mlStats.diversity.count; got < minSamplesForZScore {
		t.Errorf("expected the diversity baseline to have accumulated at least %d real samples, got %d", minSamplesForZScore, got)
	}
	if len(blocker.calls) != 0 {
		t.Errorf("expected zero Block calls across the whole run, got %+v", blocker.calls)
	}
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected no ml_score anomaly across the whole run, got %+v", writer.anomalies)
		}
	}
}

// stateSnapshot is a fully comparable projection of identityState: every
// scalar, plus map cardinalities (the maps themselves are shared by
// reference, so copying the struct alone would not notice a mutation made
// through the shared map).
type stateSnapshot struct {
	prevTotal, prevToolCalls, prevDeny, prevUniqueTools, prevInterArrivalN int
	prevInterArrivalSum                                                    time.Duration
	curTotal, curToolCalls, curDeny, curUniqueTools, curInterArrivalN      int
	curInterArrivalSum                                                     time.Duration
	windowStart, lastCallAt, lastSeen                                      time.Time
	allTimeTools                                                           int
	rate, diversity, denyRatio, interArrival, toolCalls                    onlineStat
}

func snapshot(st *identityState) stateSnapshot {
	return stateSnapshot{
		prevTotal:           st.prev.total,
		prevToolCalls:       st.prev.toolCalls,
		prevDeny:            st.prev.deny,
		prevUniqueTools:     len(st.prev.uniqueTools),
		prevInterArrivalN:   st.prev.interArrivalN,
		prevInterArrivalSum: st.prev.interArrivalSum,
		curTotal:            st.cur.total,
		curToolCalls:        st.cur.toolCalls,
		curDeny:             st.cur.deny,
		curUniqueTools:      len(st.cur.uniqueTools),
		curInterArrivalN:    st.cur.interArrivalN,
		curInterArrivalSum:  st.cur.interArrivalSum,
		windowStart:         st.windowStart,
		lastCallAt:          st.lastCallAt,
		lastSeen:            st.lastSeen,
		allTimeTools:        len(st.tools),
		rate:                st.mlStats.rate,
		diversity:           st.mlStats.diversity,
		denyRatio:           st.mlStats.denyRatio,
		interArrival:        st.mlStats.interArrival,
		toolCalls:           st.mlStats.toolCalls,
	}
}

// TestDetector_MLScore_BlockedEntriesExcludedFromState is the regression
// gate for N3. Without the "blocked" guard in recordAndCheck, a blocked
// identity's own rejected retries -- or its silence, which produces
// near-empty windows -- form new windows that score as anomalous by
// construction, and since fix wave 1 stopped folding flagged windows into
// the baseline, the baseline never absorbs them. Block() then fires again
// at every window rollover and BlockChecker.Block rewrites `until` each
// time, so the identity never recovers from what README.md documents as a
// strictly time-bounded block.
func TestDetector_MLScore_BlockedEntriesExcludedFromState(t *testing.T) {
	clock := &internalClock{t: time.Unix(0, 0)}
	writer := &nopWriter{}
	blocker := &blockRecorder{}
	d := NewDetector(mlFloorCfg(), writer, nil, blocker, nil, clock.now)

	// Same 10-window {10, 11} baseline as the MinCalls test above.
	for i := 0; i < 10; i++ {
		n := 10 + i%2
		feedWindow(d, clock, "alice", distinctTools(n), n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	// A genuinely wild window: 200 calls across 20 tools, 1ms apart.
	// z_rate = (200 - 10.5) / 3.2404 = 58.48 against zCount's count floor
	// (sqrt(10.5), above the 1.575 relative floor) -- far past the 4.0 block
	// threshold.
	feedWindow(d, clock, "alice", distinctTools(20), 200, time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 1 {
		t.Fatalf("test setup: expected exactly 1 Block call for the wild window, got %d: %+v", len(blocker.calls), blocker.calls)
	}
	before := snapshot(d.state[tenantIdentityKey("", "alice")])

	// The block is now in force, so every subsequent call from alice is
	// rejected by the proxy's gate and recorded as decision "blocked" with
	// an empty Tool. Simulate both real blocked-client behaviors across
	// five window durations: a client that retries hard (200 rejected
	// calls) and a client that honors Retry-After (one lone probe).
	for w := 0; w < 5; w++ {
		retries := 200
		if w%2 == 1 {
			retries = 1
		}
		for i := 0; i < retries; i++ {
			d.Publish(auditdomain.Entry{Identity: "alice", Tool: "", Decision: "blocked"})
			clock.t = clock.t.Add(time.Millisecond)
		}
		clock.t = clock.t.Add(61 * time.Second)
	}

	if after := snapshot(d.state[tenantIdentityKey("", "alice")]); !reflect.DeepEqual(before, after) {
		t.Errorf("blocked entries mutated Detector state -- the first real call after the block expires must be scored as if the block never happened\nbefore: %+v\nafter:  %+v", before, after)
	}
	if len(blocker.calls) != 1 {
		t.Errorf("expected the block to stay at exactly 1 Block call across 5 window rollovers of blocked traffic, got %d: %+v", len(blocker.calls), blocker.calls)
	}
}
