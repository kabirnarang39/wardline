package usecase

// These tests live in package usecase (not usecase_test like the rest of
// detector_test.go) because they assert on Detector's unexported
// per-identity state directly: "a sub-floor window folds nothing into the
// baseline" is a claim about internal state that no externally-observable
// output distinguishes from a coincidence.

import (
	"fmt"
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
