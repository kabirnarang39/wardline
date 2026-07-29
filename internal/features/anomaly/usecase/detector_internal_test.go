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

func (b *blockRecorder) Block(identity, reason string) {
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
// the baseline?" is observable through.
type baselineSampleCounts struct {
	rate, diversity, denyRatio, interArrival int64
}

func sampleCounts(st *identityState) baselineSampleCounts {
	return baselineSampleCounts{
		rate:         st.mlStats.rate.count,
		diversity:    st.mlStats.diversity.count,
		denyRatio:    st.mlStats.denyRatio.count,
		interArrival: st.mlStats.interArrival.count,
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
// sample stddev 0.5345), a 1-call window scores
// z_rate = (1 - 10.5) / 0.5345 = -17.8 -- far past both the 3.0 log
// threshold and the 4.0 block threshold. An identity that simply went
// quiet for one window would be auto-blocked. With the floor, the window
// is skipped outright: no anomaly, nothing folded, no Block call.
func TestDetector_MLScore_MinCallsFloor_SkipsSingleCallWindow(t *testing.T) {
	clock := &internalClock{t: time.Unix(0, 0)}
	writer := &nopWriter{}
	blocker := &blockRecorder{}
	d := NewDetector(mlFloorCfg(), writer, nil, blocker, nil, clock.now)

	// 10 baseline windows alternating 10 and 11 calls, one distinct tool
	// per call at a fixed 1s spacing, so rate is the only feature with
	// non-zero variance (diversity is a constant 1.0, deny ratio a
	// constant 0, mean inter-arrival a constant 1s -- all zero-variance,
	// so their ZScore is 0 regardless). A window is scored and folded by
	// the first call of the *following* window, so 10 published windows
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

	st := d.state["alice"]
	before := sampleCounts(st)
	if before.rate != 10 {
		t.Fatalf("test setup: expected 10 folded baseline samples before the 1-call window, got %+v", before)
	}

	// Roll over again: this is the call that scores the 1-call window.
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if after := sampleCounts(d.state["alice"]); after != before {
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
	rate, diversity, denyRatio, interArrival                               onlineStat
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
	// z_rate = (200 - 10.5) / 1.575 = 120.3 against the relative-stddev
	// floor -- far past the 4.0 block threshold.
	feedWindow(d, clock, "alice", distinctTools(20), 200, time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 1 {
		t.Fatalf("test setup: expected exactly 1 Block call for the wild window, got %d: %+v", len(blocker.calls), blocker.calls)
	}
	before := snapshot(d.state["alice"])

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

	if after := snapshot(d.state["alice"]); !reflect.DeepEqual(before, after) {
		t.Errorf("blocked entries mutated Detector state -- the first real call after the block expires must be scored as if the block never happened\nbefore: %+v\nafter:  %+v", before, after)
	}
	if len(blocker.calls) != 1 {
		t.Errorf("expected the block to stay at exactly 1 Block call across 5 window rollovers of blocked traffic, got %d: %+v", len(blocker.calls), blocker.calls)
	}
}
