package usecase_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type recordingWriter struct {
	anomalies []domain.Anomaly
}

func (w *recordingWriter) Write(a domain.Anomaly) error {
	w.anomalies = append(w.anomalies, a)
	return nil
}

func baseCfg() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds:    60,
		RateSpikeEnabled: true,
		RateMultiplier:   3.0,
		RateMinCalls:     10,
	}
}

// fakeClock returns whatever time is currently set on t and does not
// auto-advance -- a test publishes N entries "in the same window" by
// leaving t unchanged, or forces a window rotation by jumping t forward
// explicitly (clock.t = clock.t.Add(...)).
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time {
	return c.t
}

func TestDetector_RateSpike_AboveMultiplierAndFloorFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, nil, clock.now)

	// Baseline window: 10 calls.
	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}
	// Rotate into a new window.
	clock.t = clock.t.Add(61 * time.Second)
	// Next window: 10*3+1 = 31 calls -- above both the multiplier and the
	// min-calls floor.
	for i := 0; i < 31; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	found := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a rate_spike anomaly, got %+v", writer.anomalies)
	}
}

func TestDetector_RateSpike_BelowMultiplierNeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, nil, clock.now)

	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	// 10*3-1 = 29 -- below the multiplier threshold.
	for i := 0; i < 29; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike {
			t.Errorf("expected no rate_spike anomaly below the multiplier, got %+v", writer.anomalies)
		}
	}
}

func TestDetector_RateSpike_BelowMinCallsFloorNeverFlagsRegardlessOfMultiplier(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := baseCfg()
	cfg.RateMinCalls = 10
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	// Baseline: 1 call.
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	clock.t = clock.t.Add(61 * time.Second)
	// Next window: 3 calls -- a 3x "spike" over baseline, but the absolute
	// count (3) is below RateMinCalls (10), so it must not flag.
	for i := 0; i < 3; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike {
			t.Errorf("expected no rate_spike anomaly below the min-calls floor, got %+v", writer.anomalies)
		}
	}
}

func TestDetector_RateSpike_DisabledNeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := baseCfg()
	cfg.RateSpikeEnabled = false
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	for i := 0; i < 100; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike {
			t.Errorf("expected no rate_spike anomaly when the heuristic is disabled, got %+v", writer.anomalies)
		}
	}
}

func TestDetector_RateSpike_SustainedSpikeFlagsOnlyOnce(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, nil, clock.now)

	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	// A sustained spike: 50 calls in the same window, every call from the
	// 31st onward is individually above threshold -- must still flag
	// exactly once per window, not once per call.
	for i := 0; i < 50; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	count := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 rate_spike anomaly for a sustained spike, got %d: %+v", count, writer.anomalies)
	}
}

func TestDetector_NovelTool_FirstCallFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60, NovelToolEnabled: true}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	found := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindNovelTool {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a novel_tool anomaly on the first call to a tool, got %+v", writer.anomalies)
	}
}

func TestDetector_NovelTool_SecondCallSameToolDoesNotFlag(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60, NovelToolEnabled: true}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	count := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindNovelTool {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 novel_tool anomaly (first call only), got %d", count)
	}
}

func TestDetector_NovelTool_SameToolDifferentIdentityFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60, NovelToolEnabled: true}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	d.Publish(auditdomain.Entry{Identity: "bob", Tool: "read_file", Decision: "allow"})

	bobFlagged := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindNovelTool && a.Identity == "bob" {
			bobFlagged = true
		}
	}
	if !bobFlagged {
		t.Error("expected bob's first call to read_file to flag, even though alice already called it")
	}
}

func TestDetector_NovelTool_DisabledNeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60, NovelToolEnabled: false}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindNovelTool {
			t.Errorf("expected no novel_tool anomaly when the heuristic is disabled, got %+v", writer.anomalies)
		}
	}
}

func denyRateCfg() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds:        60,
		DenyRateSpikeEnabled: true,
		DenyRateThreshold:    0.5,
		DenyRateMinCalls:     5,
	}
}

func TestDetector_DenyRateSpike_AboveThresholdAndFloorFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(denyRateCfg(), writer, nil, nil, nil, clock.now)

	// 3 deny out of 5 = 0.6 -- above the 0.5 threshold, at the min-calls floor.
	for i := 0; i < 3; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})
	}
	for i := 0; i < 2; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	found := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindDenyRateSpike {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a deny_rate_spike anomaly, got %+v", writer.anomalies)
	}
}

func TestDetector_DenyRateSpike_BelowThresholdNeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(denyRateCfg(), writer, nil, nil, nil, clock.now)

	// 2 deny out of 5 = 0.4 -- below the 0.5 threshold.
	for i := 0; i < 2; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})
	}
	for i := 0; i < 3; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindDenyRateSpike {
			t.Errorf("expected no deny_rate_spike anomaly below threshold, got %+v", writer.anomalies)
		}
	}
}

func TestDetector_DenyRateSpike_BelowMinCallsFloorNeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(denyRateCfg(), writer, nil, nil, nil, clock.now)

	// 1 deny out of 1 call = 1.0 ratio, but far below DenyRateMinCalls (5).
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindDenyRateSpike {
			t.Errorf("expected no deny_rate_spike anomaly below the min-calls floor, got %+v", writer.anomalies)
		}
	}
}

func TestDetector_DenyRateSpike_DisabledNeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := denyRateCfg()
	cfg.DenyRateSpikeEnabled = false
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	for i := 0; i < 5; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})
	}

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindDenyRateSpike {
			t.Errorf("expected no deny_rate_spike anomaly when the heuristic is disabled, got %+v", writer.anomalies)
		}
	}
}

func TestDetector_DenyRateSpike_SustainedSpikeFlagsOnlyOnce(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(denyRateCfg(), writer, nil, nil, nil, clock.now)

	// A sustained deny spike: 20 deny calls in a row, every call from the
	// 5th onward (min-calls floor) is individually above threshold -- must
	// still flag exactly once per window, not once per call.
	for i := 0; i < 20; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})
	}

	count := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindDenyRateSpike {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 deny_rate_spike anomaly for a sustained spike, got %d: %+v", count, writer.anomalies)
	}
}

func TestDetector_RateSpike_IsolatedPerIdentity(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, nil, clock.now)

	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	// bob has never been seen before -- his first window of 31 calls has
	// no baseline (prev.total == 0), so rate-spike (a baseline-relative
	// heuristic) must not fire for him from this alone.
	for i := 0; i < 31; i++ {
		d.Publish(auditdomain.Entry{Identity: "bob", Tool: "read_file", Decision: "allow"})
	}

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike && a.Identity == "bob" {
			t.Errorf("expected no rate_spike anomaly for bob with no baseline window, got %+v", writer.anomalies)
		}
	}
}

// The proxy records more than tool calls on the same audit stream the
// Detector consumes: MCP protocol-lifecycle methods land as decision
// "passthrough" with Tool set to the method name, and unparsable bodies
// land as decision "error" with Tool "". Neither is a tool call, and
// neither may reach the novel-tool set -- otherwise every identity's
// first handshake produces three guaranteed false positives.
func TestDetector_NovelTool_IgnoresProtocolPassthroughAndToollessEntries(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60, NovelToolEnabled: true}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "initialize", Decision: "passthrough"})
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "notifications/initialized", Decision: "passthrough"})
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "tools/list", Decision: "passthrough"})
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "", Decision: "error"})

	if len(writer.anomalies) != 0 {
		t.Fatalf("expected no anomalies from protocol/tool-less entries, got %+v", writer.anomalies)
	}

	// A real tool call on the same identity must still flag.
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	if len(writer.anomalies) != 1 || writer.anomalies[0].Kind != domain.KindNovelTool {
		t.Fatalf("expected the real tool call to still flag novel_tool, got %+v", writer.anomalies)
	}
}

// Protocol passthrough entries must stay out of deny-rate-spike's
// denominator: counting them dilutes the ratio and can suppress a real
// deny spike (4 denies out of 5 tool calls is 0.8, but 4 out of 5 tool
// calls plus 3 handshake entries is 0.5 -- at, not above, a 0.5
// threshold).
func TestDetector_DenyRateSpike_ProtocolPassthroughDoesNotDiluteRatio(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(denyRateCfg(), writer, nil, nil, nil, clock.now)

	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "initialize", Decision: "passthrough"})
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "notifications/initialized", Decision: "passthrough"})
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "tools/list", Decision: "passthrough"})
	for i := 0; i < 4; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "delete_file", Decision: "deny"})
	}
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	found := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindDenyRateSpike {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a deny_rate_spike anomaly (4 denies of 5 tool calls = 0.8), got %+v", writer.anomalies)
	}
}

// Rate spike stays volumetric over *all* of an identity's traffic, so
// protocol passthrough still counts toward the window totals -- a flood
// of handshake or unparsable requests is still a rate spike.
func TestDetector_RateSpike_CountsProtocolPassthroughInWindowTotals(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, nil, clock.now)

	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "tools/list", Decision: "passthrough"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	for i := 0; i < 31; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "tools/list", Decision: "passthrough"})
	}

	found := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindRateSpike {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a rate_spike anomaly from passthrough traffic alone, got %+v", writer.anomalies)
	}
}

// Both volumetric heuristics latch on the same flaggedThisWindow map,
// keyed by their own Kind. Firing one must not suppress the other, and a
// window rotation must clear both.
func TestDetector_RateAndDenySpikeLatchesDoNotCrossContaminate(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := baseCfg()
	cfg.DenyRateSpikeEnabled = true
	cfg.DenyRateThreshold = 0.5
	cfg.DenyRateMinCalls = 5
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	// Baseline window: 10 allows.
	for i := 0; i < 10; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	// Spike window: 31 denies trips both the rate multiplier (10*3) and
	// the deny ratio (1.0), each exactly once.
	for i := 0; i < 31; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})
	}

	counts := map[domain.Kind]int{}
	for _, a := range writer.anomalies {
		counts[a.Kind]++
	}
	if counts[domain.KindRateSpike] != 1 || counts[domain.KindDenyRateSpike] != 1 {
		t.Fatalf("expected exactly one of each volumetric kind, got %+v", counts)
	}

	// Rotate: both latches must clear, so the same sustained pattern fires
	// once more in the new window.
	clock.t = clock.t.Add(61 * time.Second)
	for i := 0; i < 100; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "deny"})
	}
	counts = map[domain.Kind]int{}
	for _, a := range writer.anomalies {
		counts[a.Kind]++
	}
	if counts[domain.KindRateSpike] != 2 || counts[domain.KindDenyRateSpike] != 2 {
		t.Fatalf("expected each latch to reset on window rotation, got %+v", counts)
	}
}

func mlScoreBaseCfg() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore: domain.MLScoreConfig{
			Enabled:        true,
			ScoreThreshold: 3.0,
		},
	}
}

// publishWindow feeds n calls (cycling through tools) into d, advancing
// clock.t by spacing after each call -- this is what gives a window's
// interArrivalSum/N (and, across a window boundary, the deliberately
// simplified first-delta-of-a-new-window behavior) real, non-zero values,
// instead of every call landing at the same fake instant.
func publishWindow(d *usecase.Detector, clock *fakeClock, identity string, tools []string, decision string, n int, spacing time.Duration) {
	for i := 0; i < n; i++ {
		d.Publish(auditdomain.Entry{Identity: identity, Tool: tools[i%len(tools)], Decision: decision})
		clock.t = clock.t.Add(spacing)
	}
}

// manyToolNames returns n distinct tool names, for windows whose whole
// point is a high per-window tool-diversity feature.
func manyToolNames(n int) []string {
	tools := make([]string, n)
	for i := range tools {
		tools[i] = fmt.Sprintf("tool_%d", i)
	}
	return tools
}

// establishMLBaseline feeds windows worth of mild, non-identical baseline
// traffic (alternating 5 vs 6 calls, 1 vs 2 tools) into d so each
// mlFeatureState baseline has both a non-zero mean and non-zero variance
// -- and, once windows >= minSamplesForZScore (8), enough history for
// onlineStat.ZScore to actually produce a non-zero score for whatever
// window comes next instead of the "not enough history yet" 0.
func establishMLBaseline(d *usecase.Detector, clock *fakeClock, identity string, windows int) {
	for i := 0; i < windows; i++ {
		if i%2 == 0 {
			publishWindow(d, clock, identity, []string{"read_file"}, "allow", 5, time.Second)
		} else {
			publishWindow(d, clock, identity, []string{"read_file", "list_dir"}, "allow", 6, 1200*time.Millisecond)
		}
		clock.t = clock.t.Add(61 * time.Second) // rotate: scores and folds this window into st.mlStats
	}
}

func TestDetector_MLScore_FlagsWildOutlierAfterBaselineEstablished(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(mlScoreBaseCfg(), writer, nil, nil, nil, clock.now)

	// 8 baseline windows -- minSamplesForZScore, the floor below which a
	// sample stddev is noise rather than signal (see C1).
	establishMLBaseline(d, clock, "alice", 8)

	// Wild multi-dimensional outlier window: huge call count, many
	// distinct tools, a tight burst (near-zero intra-window spacing).
	publishWindow(d, clock, "alice", manyToolNames(20), "allow", 200, time.Millisecond)

	// Rotate once more: this is the call that scores the wild window
	// (now st.prev) against the established baseline (mlStats count == 2).
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	var found *domain.Anomaly
	for i, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			found = &writer.anomalies[i]
		}
	}
	if found == nil {
		t.Fatalf("expected an ml_score anomaly for the wild outlier window, got %+v", writer.anomalies)
	}
	if found.Detail == "" {
		t.Error("expected a non-empty Detail naming a driving feature")
	}
}

func TestDetector_MLScore_NoAnomalyBeforeBaselineEstablished(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore:       domain.MLScoreConfig{Enabled: true, ScoreThreshold: 0},
	}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	// alice's very first window ever, made as extreme as possible.
	publishWindow(d, clock, "alice", manyToolNames(20), "allow", 200, time.Millisecond)

	// Rotate: this scores alice's first completed window. mlStats has
	// zero history (count == 0 < 2) for every feature, so ZScore returns 0
	// regardless of how extreme window1's traffic was.
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected no ml_score anomaly on an identity's first window (no baseline yet), got %+v", writer.anomalies)
		}
	}
}

func TestDetector_MLScore_OnePerWindow_NotOnePerCall(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(mlScoreBaseCfg(), writer, nil, nil, nil, clock.now)

	establishMLBaseline(d, clock, "alice", 8)
	publishWindow(d, clock, "alice", manyToolNames(20), "allow", 200, time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)

	// The wild window (now st.prev) is scored exactly once: by the single
	// call whose arrival crosses the boundary into the next window. Many
	// more calls following in that same next window must not re-score it
	// (each would re-fold the same completed window into st.mlStats and
	// re-emit the anomaly if checkMLScore were wired to run on every call
	// instead of being gated to the one rollover call).
	for i := 0; i < 20; i++ {
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	count := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 ml_score anomaly for a sustained wild-outlier window, got %d: %+v", count, writer.anomalies)
	}
}

func TestDetector_MLScore_DisabledFlag_NeverFires(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	cfg := mlScoreBaseCfg()
	cfg.MLScore.Enabled = false
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now)

	publishWindow(d, clock, "alice", []string{"read_file"}, "allow", 5, time.Second)
	clock.t = clock.t.Add(61 * time.Second)
	publishWindow(d, clock, "alice", []string{"read_file", "list_dir"}, "allow", 6, 1200*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	publishWindow(d, clock, "alice", manyToolNames(20), "allow", 200, time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected no ml_score anomaly when the heuristic is disabled, got %+v", writer.anomalies)
		}
	}
}

// TestDetector_MLScore_OrdinaryVaryingTraffic_NeverFalsePositives is the
// regression gate for C1 (and C3, transitively, since C3's lastCallAt
// reset means every window here compares like-for-like inter-arrival
// gaps): every other ml_score test above drives a wild outlier and
// asserts detection fires; nothing asserted the ABSENCE of a false
// positive on ordinary, mildly-varying traffic until now. The rate
// sequence below (10/11 alternating) is the reviewer's exact
// reproduction: under the old count<2 floor, a baseline of {10, 11}
// produced z=7.78 (an auto-block) for a third window of an entirely
// ordinary 50% swing. deny-ratio and inter-arrival are held constant (no
// denies, fixed 1s spacing, and lastCallAt resetting every rollover keeps
// that spacing honest) so they score 0; tool_diversity is a raw
// distinct-tool count that manyToolNames(n) pins to the call count, so it
// moves in lockstep with rate and scores identically to it, never
// overtaking it (maxAbsZ compares call_rate first, strict >). Either way
// the assertion isolates exactly the rate dimension the false positive
// fired on.
func TestDetector_MLScore_OrdinaryVaryingTraffic_NeverFalsePositives(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(mlScoreBaseCfg(), writer, nil, nil, nil, clock.now)

	rates := []int{10, 11, 10, 11, 10, 11, 10, 11, 10, 11, 10, 11, 10, 11, 10, 11}
	for _, n := range rates {
		publishWindow(d, clock, "alice", manyToolNames(n), "allow", n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}
	// One more call to score the final window.
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected zero ml_score anomalies on ordinary, mildly-varying traffic, got %+v", writer.anomalies)
		}
	}
}

// TestDetector_MLScore_RepeatIdenticalAttacks_AllFlagged is the
// regression gate for C2, whose fix (only fold a window into the baseline
// when it wasn't itself flagged) was verified empirically in fix wave 1
// but never turned into a test. Before that fix, folding a flagged window
// in unconditionally dragged the baseline's variance so wide that an
// identical repeat of the same attack stopped scoring anomalous after
// round one -- 4 identical bursts, only the first flagged.
//
// Each burst is 200 calls across 20 tools 1ms apart, scored against a
// frozen 8-sample {10, 11} baseline (mean 10.5, stddev floored by zCount to
// max(0.15*10.5 = 1.575, sqrt(10.5) = 3.2404) = 3.2404):
// z_rate = (200-10.5)/3.2404 = 58.48 every time, far past both the 3.0 log
// threshold and the 4.0 block threshold. "Frozen" is
// the whole point: because no burst is folded, burst 4 is compared against
// exactly the same baseline burst 1 was.
func TestDetector_MLScore_RepeatIdenticalAttacks_AllFlagged(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore:       domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0, MinCalls: 5},
		AutoBlock:     domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 4.0, BlockDurationSeconds: 300},
	}
	d := usecase.NewDetector(cfg, writer, nil, blocker, nil, clock.now)

	for _, n := range []int{10, 11, 10, 11, 10, 11, 10, 11} {
		publishWindow(d, clock, "alice", manyToolNames(n), "allow", n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	// 4 identical bursts. Burst i is scored by the first call of burst i+1,
	// so the 4th needs one trailing rollover call of its own.
	const bursts = 4
	for i := 0; i < bursts; i++ {
		publishWindow(d, clock, "alice", manyToolNames(20), "allow", 200, time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
	}
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	count := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			count++
		}
	}
	if count != bursts {
		t.Errorf("expected all %d identical attack bursts to be flagged, got %d: %+v", bursts, count, writer.anomalies)
	}
	if len(blocker.calls) != bursts {
		t.Errorf("expected all %d identical attack bursts to trigger Block, got %d: %+v", bursts, len(blocker.calls), blocker.calls)
	}
}

// TestDetector_MLScore_OrdinaryGrowth_NeverFlags is the end-to-end
// (Detector-level) regression gate for the remainder of N1: the reviewer's
// exact repro, driven through Publish rather than onlineStat directly.
// Baseline {10, 11} alternating x8 gives mean 10.5 and sample stddev
// 0.5345; a following window of 13 calls is a 24% increase -- ordinary
// traffic variation. Unfloored that scores z = (13-10.5)/0.5345 = 4.68,
// which clears BOTH thresholds below: it would log an anomaly and
// auto-block the identity. zCount floors the divisor at
// max(0.15*10.5 = 1.575, sqrt(10.5) = 3.2404) = 3.2404 and the same window
// scores 0.77 (1.59 under the relative floor alone).
func TestDetector_MLScore_OrdinaryGrowth_NeverFlags(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore:       domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0, MinCalls: 5},
		AutoBlock:     domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 4.0, BlockDurationSeconds: 300},
	}
	d := usecase.NewDetector(cfg, writer, nil, blocker, nil, clock.now)

	// A fixed 1s spacing holds mean inter-arrival at a constant 1s, so that
	// feature has zero variance and, its relative floor being the only
	// divisor left, scores 0. tool_diversity does NOT sit still here:
	// manyToolNames(n) hands n calls n distinct names, so the raw
	// distinct-tool count round 5 switched this feature to tracks the call
	// count exactly (10/11 in the baseline, 13 in the target window). It has
	// the same mean, the same variance and therefore the same z as call_rate
	// at every step, so it can never overtake it -- maxAbsZ/maxHarmfulZ
	// compare call_rate first and only replace it on a strict >. That, not a
	// constant-1.0 diversity, is why this test's assertions isolate rate.
	for _, n := range []int{10, 11, 10, 11, 10, 11, 10, 11} {
		publishWindow(d, clock, "alice", manyToolNames(n), "allow", n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	// The 13-call window. Its first call folds baseline window 8, bringing
	// mlStats.rate to the 8 samples minSamplesForZScore requires.
	publishWindow(d, clock, "alice", manyToolNames(13), "allow", 13, time.Second)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			t.Errorf("expected no ml_score anomaly for a 24%% traffic increase over a naturally tight baseline, got %+v", writer.anomalies)
		}
	}
	if len(blocker.calls) != 0 {
		t.Errorf("expected zero Block calls for a 24%% traffic increase, got %+v", blocker.calls)
	}
}

// recordingBlocker is a test double for the blocker interface, so a test
// can assert on whether Block was called at all, not just what an
// anomaly writer recorded.
type recordingBlocker struct {
	calls []struct{ identity, reason string }
}

func (b *recordingBlocker) Block(identity, reason string) {
	b.calls = append(b.calls, struct{ identity, reason string }{identity, reason})
}

// TestDetector_MLScore_LogsBelowAutoBlockThreshold_NeverBlocks proves the
// two-threshold design actually works: ml_score.score_threshold (3.0) is
// lower than auto_block.score_threshold (8.0), so an operator can "log
// at a lower sensitivity than they block at" -- traffic scoring between
// the two must produce exactly one ml_score anomaly and zero Block
// calls. Nothing before this test drove a score in that gap with a
// blocker wired in to observe it.
func TestDetector_MLScore_LogsBelowAutoBlockThreshold_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore:       domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0},
		AutoBlock:     domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 8.0, BlockDurationSeconds: 300},
	}
	d := usecase.NewDetector(cfg, writer, nil, blocker, nil, clock.now)

	// 8 baseline windows alternating rate 10/12 (mean 11, m2 = 8, so
	// sample stddev sqrt(8/7) = 1.069, under zCount's sqrt(11) = 3.3166
	// count floor); deny-ratio and inter-arrival held
	// constant (no denies, fixed 1s spacing) so they score 0, and
	// tool_diversity -- a raw distinct-tool count that manyToolNames(n)
	// pins to the call count -- moves in lockstep with rate and scores
	// identically to it, so rate is what the score reports (maxAbsZ
	// compares call_rate first, strict >).
	baseRates := []int{10, 12, 10, 12, 10, 12, 10, 12}
	for _, n := range baseRates {
		publishWindow(d, clock, "alice", manyToolNames(n), "allow", n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	// Target window: rate 29. zCount floors the divisor at
	// max(1.069 raw, 0.15*11 = 1.65, sqrt(11) = 3.3166) = 3.3166, so
	// z = (29-11)/3.3166 = 5.43 -- real margin on both sides of the 3.0 log
	// threshold and the 8.0 block threshold.
	//
	// The driving rate has been raised twice to hold that margin as the floor
	// this test's divisor comes from grew, and each time only the synthetic
	// input moved, never an assertion or a threshold: 16 (scored 3.03 against
	// the relative floor, clearing the log threshold by 0.03 -- a premise
	// that was a coin flip), then 20 (scored 5.45 against the same floor),
	// now 29 against round 11's sqrt(mean) count floor, at which 20 would
	// have scored only 2.71 and logged nothing at all. The claim under test
	// is the two-threshold design itself -- a score in the gap logs once and
	// never blocks -- which is orthogonal to how wide the divisor is.
	publishWindow(d, clock, "alice", manyToolNames(29), "allow", 29, time.Second)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	count := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindMLScore {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 ml_score anomaly logged between the two thresholds, got %d: %+v", count, writer.anomalies)
	}
	if len(blocker.calls) != 0 {
		t.Fatalf("expected zero Block calls for a score below auto_block.score_threshold, got %+v", blocker.calls)
	}
}

// declineCfg is the shipped example config's ml_score/auto_block shape
// (log at 3.0, block at 4.0, skip windows under 5 calls) scaled to a 60s
// window -- the exact config the three traffic-decline tests below are
// reproductions against.
func declineCfg() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore:       domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0, MinCalls: 5},
		AutoBlock:     domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 4.0, BlockDurationSeconds: 300},
	}
}

// mlScoreAnomalies filters w's record down to the ml_score kind, so a test
// can assert on both "the decline was still logged" and "nothing was
// blocked for it" without re-walking the slice twice.
func mlScoreAnomalies(w *recordingWriter) []domain.Anomaly {
	var out []domain.Anomaly
	for _, a := range w.anomalies {
		if a.Kind == domain.KindMLScore {
			out = append(out, a)
		}
	}
	return out
}

// TestDetector_MLScore_TrafficDecline_NeverBlocks is the regression gate for
// the one-sided auto-block gate (maxHarmfulZ). It is the reviewer's exact
// reproduction: a busy identity settles into a 95-105 calls/window baseline
// (11 folded samples, mean 100.4545, raw stddev 2.8762 floored per
// minStddevRelFraction to 0.15*100.4545 = 15.0682), then quiets down to 30
// calls -- z_rate = (30 - 100.4545) / 15.0682 = -4.68.
//
// Under the old two-sided |z| gate that magnitude cleared
// auto_block.score_threshold (4.0) and blocked the identity for going
// *quiet*; worse, a flagged window is never folded into the baseline, so
// the mean stayed pinned at 100.4545 and every following 30-call window
// re-blocked forever. MinCalls (5) is no defense here: 30 is well above it.
// The anomaly is still LOGGED (the two-sided score is what the log record
// uses, deliberately -- "this identity went unusually quiet" is useful
// telemetry); only the Block call must not happen.
func TestDetector_MLScore_TrafficDecline_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	// 11 published windows leave 10 folded; the decline window's own first
	// call folds the 11th, so the decline is scored against exactly the
	// 11-sample baseline traced above (sum 1105 / 11 = 100.4545). A fixed
	// 200ms spacing holds mean inter-arrival at 200ms and there are no
	// denies, so both those features have zero variance and score 0.
	// tool_diversity is a raw distinct-tool count and manyToolNames(n) pins
	// it to the call count, so it has the same mean, variance and z as
	// call_rate in every window including the decline (-4.68 here too) --
	// identical, never larger, so call_rate is what maxAbsZ reports (strict
	// >) and the assertion still isolates the rate dimension. Both features
	// point the same benign direction, so neither can block. 200ms, not 1s: at these call
	// counts a 1s spacing would carry a window past its own 60s boundary
	// mid-publish, splitting it into two and destroying the baseline this
	// test is built on.
	for _, n := range []int{95, 105, 96, 104, 97, 103, 98, 102, 99, 101, 105} {
		publishWindow(d, clock, "alice", manyToolNames(n), "allow", n, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
	}

	publishWindow(d, clock, "alice", manyToolNames(30), "allow", 30, 200*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("a traffic decline must never auto-block, got %+v", blocker.calls)
	}
	// Guards against a vacuous pass: without this, a test whose baseline
	// silently failed to establish (every ZScore 0) would also report zero
	// Block calls. The logged score pins the traced arithmetic.
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the decline to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 4.68 (driving feature: call_rate)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// publishMixedWindow feeds n calls, the first denyCount of them recorded as
// policy denials, each with its own distinct tool name. publishWindow can't
// produce this shape (one decision for every call), and deny_ratio needs a
// window that is neither all-allow nor all-deny to have a baseline with
// non-zero variance.
func publishMixedWindow(d *usecase.Detector, clock *fakeClock, identity string, n, denyCount int, spacing time.Duration) {
	for i := 0; i < n; i++ {
		decision := "allow"
		if i < denyCount {
			decision = "deny"
		}
		d.Publish(auditdomain.Entry{Identity: identity, Tool: fmt.Sprintf("tool_%d", i), Decision: decision})
		clock.t = clock.t.Add(spacing)
	}
}

// TestDetector_MLScore_DenyRatioDropsToZero_NeverBlocks is the reviewer's
// second, independent reproduction of the same root cause on a different
// feature: an identity whose policy denials *stop* (an operator widened a
// rule, a misconfigured client got fixed) must not be auto-blocked for it.
//
// 20 calls/window throughout with denials alternating 6 and 7 gives an
// 11-sample deny-ratio baseline of six 0.30s and five 0.35s: mean 0.3227,
// raw stddev 0.0261, floored to 0.15*0.3227 = 0.0484. A window with zero
// denies scores z_deny = (0 - 0.3227) / 0.0484 = -6.67 -- past the 4.0
// block threshold in magnitude under the old two-sided gate. Rate,
// diversity and inter-arrival are constant (20 calls, one distinct tool
// each, 1s spacing) so deny_ratio is the only feature with any signal.
func TestDetector_MLScore_DenyRatioDropsToZero_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	for i := 0; i < 11; i++ {
		publishMixedWindow(d, clock, "alice", 20, 6+i%2, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	publishMixedWindow(d, clock, "alice", 20, 0, time.Second)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("a deny ratio dropping to zero must never auto-block, got %+v", blocker.calls)
	}
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the deny-ratio drop to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 6.67 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// establishHighVolumeDenyBaseline publishes 11 windows of 200 tool calls
// with denials cycling 3/4/5, i.e. deny ratios cycling 0.015/0.02/0.025:
// mean 0.0195455, raw sample stddev 0.0041560, above the relative floor
// 0.15*0.0195455 = 0.0029318 so that floor is inert. Rate and distinct-tool
// count are a flat 200 in every window and the 200ms spacing is constant,
// so deny_ratio is the only feature with any variance -- and 200 calls per
// window is the point: it makes the baseline's stddev a statement about
// 200-observation windows specifically, which is exactly what a later
// 10-call window's noise must not be judged against.
func establishHighVolumeDenyBaseline(d *usecase.Detector, clock *fakeClock, identity string) {
	for i := 0; i < 11; i++ {
		publishMixedWindow(d, clock, identity, 200, 3+i%3, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
	}
}

// TestDetector_MLScore_DenyRatioLowVolumeNoise_NeverBlocks is the
// regression gate for deny_ratio's small-sample noise clearing the
// auto-block gate. deny_ratio is a *ratio*, so its sampling noise depends
// on how many real tool calls produced it -- something neither the
// historical stddev nor minStddevRelFraction can see, because both are
// calibrated from the baseline's own (here 200-call) window size.
//
// Hand-traced: against the 200-call baseline above, a legitimately quiet
// window of 10 tool calls with 1 denial (ratio 0.10) scores
// zDeny = (0.10-0.0195455)/0.0041560 = 19.36 -- which is what the log
// record still reports, correctly, as "this window's deny ratio is far
// off baseline". But 1-in-10 cannot distinguish 10% from 2%: the window's
// own binomial standard error, computed from the continuity-corrected
// pSmoothed = (0.0195455*8+0.5)/(8+1) = 0.0729293 (round 11 weights the
// correction by the fixed minSamplesForZScore, not this window's own
// toolCalls -- see checkMLScore's pSmoothed comment), is
// se = sqrt(0.0729293*0.9270707/10) = 0.0822257, well above the 0.0041560
// historical stddev, so the block-gating score is
// (0.10-0.0195455)/0.0822257 = 0.978 -- nowhere near the 4.0 block
// threshold. MinCalls (5) is no defense: 10 calls clears it. (Round 7's
// zRate >= 0 gate independently excludes deny_ratio here too, since
// z_rate = (10-200)/30 = -6.33; both suppressions are live, and the
// binomial floor is the one that still applies at matched volume.)
func TestDetector_MLScore_DenyRatioLowVolumeNoise_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	establishHighVolumeDenyBaseline(d, clock, "alice")

	publishMixedWindow(d, clock, "alice", 10, 1, 200*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("one denial in a 10-call window must never auto-block against a 200-call-window baseline, got %+v", blocker.calls)
	}
	// Guards against a vacuous pass: a baseline that silently failed to
	// establish would score every feature 0 and report zero Block calls too.
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the quiet window to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 19.36 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// TestDetector_MLScore_DenyRatioPassthroughInflatedTotal_NeverBlocks is the
// second half of the same root cause: MinCalls gates the window on
// windowCounts.total, which counts MCP protocol-lifecycle passthrough
// entries -- so a window can clear MinCalls without a single additional
// real tool call, leaving deny_ratio computed from a 2-observation sample.
// Every real MCP client sends initialize / notifications/initialized /
// tools/list before its first tool call, so this is the ordinary shape of
// a freshly reconnected client's first window, not a contrived one.
//
// Hand-traced: total = 5 (3 passthrough + 2 tool calls) clears MinCalls 5,
// toolCalls = 2 with 1 denial gives ratio 0.50 and
// zDeny = (0.50-0.0195455)/0.0041560 = 115.60. The block-gating score is 0
// outright: 2 real tool calls is below MinCalls, which is the "there is no
// reliable signal here at all" case rather than one to be scaled down.
func TestDetector_MLScore_DenyRatioPassthroughInflatedTotal_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	establishHighVolumeDenyBaseline(d, clock, "alice")

	for _, e := range []auditdomain.Entry{
		{Identity: "alice", Tool: "initialize", Decision: "passthrough"},
		{Identity: "alice", Tool: "notifications/initialized", Decision: "passthrough"},
		{Identity: "alice", Tool: "tools/list", Decision: "passthrough"},
		{Identity: "alice", Tool: "read_file", Decision: "deny"},
		{Identity: "alice", Tool: "list_dir", Decision: "allow"},
	} {
		d.Publish(e)
		clock.t = clock.t.Add(200 * time.Millisecond)
	}
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("one denial out of 2 real tool calls must never auto-block, however much passthrough traffic padded total, got %+v", blocker.calls)
	}
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the reconnect window to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 115.60 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// TestDetector_MLScore_DenySpike_StillBlocks is the other half of the
// binomial-standard-error floor: suppressing small-sample noise must not
// neuter real deny-spike detection. No pre-existing test drove a deny
// *increase* into a Block call at all -- every deny_ratio test before this
// one covered denials dropping (the benign direction).
//
// Round 7 turned the second subtest into a negative case: the zRate >= 0
// gate on deny_ratio's block candidacy deliberately gives up blocking a
// deny spike whose window volume collapsed. The first subtest is now the
// one that carries the "detection still works" claim -- read both together.
func TestDetector_MLScore_DenySpike_StillBlocks(t *testing.T) {
	// Ordinary window size: 20 calls/window with denials alternating 6/7
	// gives an 11-sample baseline of mean 0.3227273, raw stddev 0.0261116
	// floored per minStddevRelFraction to 0.15*0.3227273 = 0.0484091. The
	// window's own binomial standard error uses the continuity-corrected
	// pSmoothed = (0.3227273*8+0.5)/(8+1) = 0.3424242 (round 11 weights the
	// correction by the fixed minSamplesForZScore, not this window's own
	// toolCalls -- see checkMLScore's pSmoothed comment), giving
	// se = sqrt(0.3424242*0.6575758/20) = 0.1061061, which exceeds that floor
	// and so becomes the divisor. A window of 20 calls with 17 denials (0.85)
	// therefore scores (0.85-0.3227273)/0.1061061 = 4.969 -- 24% clear of
	// the 4.0 threshold. The log record keeps the unfloored
	// (0.85-0.3227273)/0.0484091 = 10.89.
	//
	// 17, not the 15 this subtest used before round 7: pSmoothed pulls the
	// baseline mean toward 0.5 and so widens se slightly (0.1045405 ->
	// 0.1061061), which drops 15 denials to (0.75-0.3227273)/0.1061061 =
	// 4.027 -- a 0.7% margin above the block threshold, i.e. an assertion
	// whose own premise was a coin flip. Volume is identical to the
	// baseline's in every case,
	// so z_rate = 0 and nothing but deny_ratio could produce this score --
	// which is also what makes this the subtest that carries the "detection
	// still works" claim after round 7's zRate >= 0 gate.
	t.Run("ordinary window size", func(t *testing.T) {
		clock := &fakeClock{t: time.Unix(0, 0)}
		writer := &recordingWriter{}
		blocker := &recordingBlocker{}
		d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

		for i := 0; i < 11; i++ {
			publishMixedWindow(d, clock, "alice", 20, 6+i%2, time.Second)
			clock.t = clock.t.Add(61 * time.Second)
		}

		publishMixedWindow(d, clock, "alice", 20, 17, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

		logged := mlScoreAnomalies(writer)
		if len(logged) != 1 {
			t.Fatalf("expected the deny spike to be logged exactly once as ml_score, got %d: %+v", len(logged), writer.anomalies)
		}
		if want := "combined z-score 10.89 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
			t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
		}
		if len(blocker.calls) != 1 {
			t.Fatalf("expected the deny spike to auto-block exactly once, got %d: %+v", len(blocker.calls), blocker.calls)
		}
		// Assert the block-gating score itself, not just the feature name:
		// this is the one subtest whose whole point is that the margin above
		// the 4.0 threshold is real, and a bare "names deny_ratio" check
		// would pass just as happily at 4.01.
		if want := "ml_score 4.97 (feature: deny_ratio)"; !strings.Contains(blocker.calls[0].reason, want) {
			t.Errorf("expected the block reason to be %q, got %q", want, blocker.calls[0].reason)
		}
	})

	// Small window, low volume relative to baseline: this subtest asserted
	// exactly the opposite (1 Block call) until round 7 gated deny_ratio's
	// auto-block candidacy on zRate >= 0. That gate deliberately gives this
	// case up, and this is the *same* class of case the gate exists to close,
	// not collateral damage: 10 tool calls against a baseline of 200-call
	// windows scores z_rate = (10-200)/30 = -6.33, so the identity's overall
	// volume collapsed -- indistinguishable, from the deny *ratio*'s point of
	// view, from the habitual-denials false positive
	// TestDetector_MLScore_DenyRatioVolumeDecline_NeverBlocks reproduces
	// (both have a shrunken denominator; only their numerator differs, and no
	// ratio-based floor can tell those apart -- the window's own binomial SE
	// shrinks as 1/sqrt(n) while the ratio artifact grows as 1/n, so
	// sqrt(n) can never cancel n). Without the gate this window's
	// block-gating score is (0.50-0.0195455)/0.0822257 = 5.84, well past the
	// 4.0 threshold.
	//
	// Accepted trade-off, matching round 4's accepted "quiet slow-drip exfil
	// is unblockable" posture: a real attack conducted at conspicuously low
	// volume is logged but not auto-blocked, because preferring a missed
	// block over a false one is this feature's stated bias. The "ordinary
	// window size" subtest above is what proves deny-spike *detection* still
	// works: its baseline and its attack window are both 20 calls, so
	// z_rate = 0, the gate passes, and it still blocks.
	t.Run("small window, low volume relative to baseline -- no longer blocks", func(t *testing.T) {
		clock := &fakeClock{t: time.Unix(0, 0)}
		writer := &recordingWriter{}
		blocker := &recordingBlocker{}
		d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

		establishHighVolumeDenyBaseline(d, clock, "alice")

		publishMixedWindow(d, clock, "alice", 10, 5, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

		if len(blocker.calls) != 0 {
			t.Fatalf("a deny ratio raised by a collapsing call volume must never auto-block, got %d: %+v", len(blocker.calls), blocker.calls)
		}
		// Guards against a vacuous pass: a baseline that silently failed to
		// establish would score every feature 0 and report zero Block calls
		// too. zDeny (the two-sided log score) is untouched by the gate:
		// (0.50-0.0195455)/0.0041560 = 115.60.
		logged := mlScoreAnomalies(writer)
		if len(logged) != 1 {
			t.Fatalf("expected the quiet high-deny window to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
		}
		if want := "combined z-score 115.60 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
			t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
		}
	})
}

// TestDetector_MLScore_DenySpikeFromCleanHistory_StillBlocks is the
// regression gate for round 7's Fix 2: an identity with a spotless deny
// history was permanently blind to its first deny spike, however severe.
// Same class of bug as round 6's zero-*variance* blind spot, but for a zero
// *mean* on a bounded [0,1] ratio: at p=0 the binomial SE sqrt(0*(1-0)/n)
// is 0 and the relative floor 0.15*0 is also 0, so both floors collapse
// simultaneously and ZScoreFloored's stddev == 0 fallback returns 0
// unconditionally.
//
// Hand-traced: 11 baseline windows of 20 calls with zero denials, then an
// attack window of 20 calls where all 20 are denied (rate, diversity and
// spacing held constant, so deny_ratio is the only signal). The continuity
// correction gives pSmoothed = (0*8+0.5)/(8+1) = 0.0555556 and
// se = sqrt(0.0555556*0.9444444/20) = 0.0512197, so the block-gating score
// is (1.0-0)/0.0512197 = 19.52 -- far past 4.0. Pre-fix: 0 anomalies, 0
// blocks, a 0%->100% deny spike completely invisible.
//
// The magnitude has moved twice as the continuity correction's
// pseudo-observation weight was re-rooted, and the outcome has not: round 8
// took it from 22.38 (weight = the baseline's folded-window count, 11) to
// 29.33 (weight = this window's own toolCalls, 20), and round 11 to 19.52
// (weight = the fixed minSamplesForZScore, 8). Round 11's move is the one
// that matters for correctness rather than calibration: a weight tied to
// toolCalls made the SE carry a 1/n factor that canceled the deny ratio's
// own, so a fixed small denial count blocked at any window size (see
// checkMLScore's pSmoothed comment and
// TestDetector_MLScore_DenyRatioFixedSmallCount_NeverBlocksRegardlessOfVolume).
// A 0%->100% spike still blocks through all three, which is this test's
// actual claim.
//
// Fix 1's zRate >= 0 gate does not interfere: volume is 20 in the attack
// window and 20 in the baseline, so z_rate = 0 exactly. The two fixes are
// independent and both necessary -- Fix 1 alone leaves this case blind
// (volume never changed), Fix 2 alone leaves Fix 1's cases blocking (their
// baseline mean is nonzero and well established).
//
// This is also the regression gate for round 9's Fix 2, the one case where a
// Block() could fire with no ml_score log record at all -- breaking the
// invariant config validation's own auto_block.score_threshold >=
// ml_score.score_threshold check (and README.md) promise: an operator must
// never see an unexplained auto-block. zDeny, the two-sided score the log
// record uses, is computed against this zero-mean, zero-variance baseline, so
// its divisor degenerates to exactly 0 and ZScoreFloored returns 0 -- while
// zDenyBlock correctly scores 19.52 and blocks. checkMLScore now promotes the
// block-gating score/feature into the log record whenever it is the larger of
// the two (structurally only possible in this degenerate case, since
// zDenyBlock's floors only ever widen zDeny's divisor), so this scenario logs
// exactly one ml_score anomaly reporting the same 19.52/deny_ratio the block
// reason does.
func TestDetector_MLScore_DenySpikeFromCleanHistory_StillBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	for i := 0; i < 11; i++ {
		publishMixedWindow(d, clock, "alice", 20, 0, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	publishMixedWindow(d, clock, "alice", 20, 20, time.Second)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 1 {
		t.Fatalf("expected a 0%%->100%% deny spike to auto-block exactly once, got %d: %+v", len(blocker.calls), blocker.calls)
	}
	// Pins the traced 19.52 rather than just the feature name: the number is
	// the whole claim here, since pre-fix this exact scenario scored 0.
	if want := "ml_score 19.52 (feature: deny_ratio)"; !strings.Contains(blocker.calls[0].reason, want) {
		t.Errorf("expected the block reason to be %q, got %q", want, blocker.calls[0].reason)
	}
	// Round 9's Fix 2: the block must be accompanied by a log record carrying
	// the same score and feature, not left unexplained.
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the block to be accompanied by exactly 1 ml_score log record, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 19.52 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the log record to report the block-gating score as %q, got %q", want, logged[0].Detail)
	}
}

// TestDetector_MLScore_DenyRatioCleanHistoryOrdinaryDenial_NeverBlocks is the
// regression gate for round 8: round 7's own continuity correction derived
// its pseudo-evidence from mlStats.denyRatio.count -- the number of baseline
// windows folded so far, which grows for as long as an identity stays
// active. At p=0 that made pSmoothed = 0.5/(count+1) shrink without bound,
// the invented SE shrink with it, and a single ordinary policy denial score
// an ever-larger z the *longer* the identity had been behaving. Running
// cleanly for longer is not a threat signal; it was scoring as one.
//
// Hand-traced, one denial in a 20-call window (ratio 0.05) against a
// spotless baseline of 20-call windows. Only the fold count differs between
// the two subtests, and that is the entire point:
//
//	fold count | pre-round-8 z                    | round-8 z | round-11 z
//	20         | 0.5/21   -> se 0.0340901 -> 1.47 | 1.47      | 0.98 (no block)
//	200        | 0.5/201  -> se 0.0111386 -> 4.49 | 1.47      | 0.98 (no block)
//
// So the 20-window subtest is the control -- it passed before round 8 too,
// because there fold count happened to equal the window's toolCalls -- and
// the 200-window subtest is the one that reproduced the bug (4.49 > the 4.0
// block threshold). Round 8 keyed the correction to this window's own
// toolCalls; round 11 keys it to the fixed minSamplesForZScore (8) instead,
// since a toolCalls-keyed weight degenerated into a raw denial count
// independent of window size (see checkMLScore's pSmoothed comment). Under
// round 11 both subtests score
// pSmoothed = (0*8+0.5)/(8+1) = 0.0555556,
// se = sqrt(0.0555556*0.9444444/20) = 0.0512197,
// z = (0.05-0)/0.0512197 = 0.9762 -- identical, and comfortably below 4.0.
//
// Round 7's zRate >= 0 gate is not what saves this case: the denial window
// is 20 calls against a 20-call baseline, so z_rate = 0 exactly and
// deny_ratio is a live block candidate. The binomial SE is doing the work.
//
// The paired spike assertion is what keeps this non-vacuous, and it carries
// the independence claim directly: the *same* baselines with a 0%->100% deny
// window must both block at exactly 19.52. Pre-round-8 those two scored
// 29.33 and 89.78 -- the same attack judged 3x more severe purely for having
// been preceded by more clean history. No ml_score log record is asserted in
// the ordinary-denial case because there is none to assert: zDeny stays 0
// against a zero-mean, zero-variance baseline and round 9's promoted
// block-gating score is only 0.9762, below the 3.0 log threshold -- which is
// also why this false positive was invisible in telemetry. (The paired spike
// does now log, via that same promotion -- see
// DenySpikeFromCleanHistory's note; this test asserts only its block, which
// is the claim it exists for.)
func TestDetector_MLScore_DenyRatioCleanHistoryOrdinaryDenial_NeverBlocks(t *testing.T) {
	establishCleanDenyBaseline := func(d *usecase.Detector, clock *fakeClock, windows int) {
		for i := 0; i < windows; i++ {
			publishMixedWindow(d, clock, "alice", 20, 0, time.Second)
			clock.t = clock.t.Add(61 * time.Second)
		}
	}
	// rollWindow closes the window publishMixedWindow just filled, so the
	// detector scores it.
	rollWindow := func(d *usecase.Detector, clock *fakeClock) {
		clock.t = clock.t.Add(61 * time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	for _, baselineWindows := range []int{20, 200} {
		t.Run(fmt.Sprintf("%d clean windows of history", baselineWindows), func(t *testing.T) {
			clock := &fakeClock{t: time.Unix(0, 0)}
			blocker := &recordingBlocker{}
			d := usecase.NewDetector(declineCfg(), &recordingWriter{}, nil, blocker, nil, clock.now)

			establishCleanDenyBaseline(d, clock, baselineWindows)
			publishMixedWindow(d, clock, "alice", 20, 1, time.Second)
			rollWindow(d, clock)

			if len(blocker.calls) != 0 {
				t.Errorf("one ordinary denial in a 20-call window must never auto-block, however long the identity has run cleanly (%d windows), got %+v", baselineWindows, blocker.calls)
			}

			// Same baseline, same window size, a real 0%->100% spike: must
			// still block, and at the same score regardless of fold count.
			spikeClock := &fakeClock{t: time.Unix(0, 0)}
			spikeBlocker := &recordingBlocker{}
			spikeD := usecase.NewDetector(declineCfg(), &recordingWriter{}, nil, spikeBlocker, nil, spikeClock.now)

			establishCleanDenyBaseline(spikeD, spikeClock, baselineWindows)
			publishMixedWindow(spikeD, spikeClock, "alice", 20, 20, time.Second)
			rollWindow(spikeD, spikeClock)

			if len(spikeBlocker.calls) != 1 {
				t.Fatalf("expected a 0%%->100%% deny spike to still auto-block exactly once after %d clean windows, got %d: %+v", baselineWindows, len(spikeBlocker.calls), spikeBlocker.calls)
			}
			if want := "ml_score 19.52 (feature: deny_ratio)"; !strings.Contains(spikeBlocker.calls[0].reason, want) {
				t.Errorf("expected the spike's block score to be %q independent of the %d-window fold count, got %q", want, baselineWindows, spikeBlocker.calls[0].reason)
			}
		})
	}
}

// TestDetector_MLScore_DenyRatioVolumeDecline_NeverBlocks is the regression
// gate for round 7's Fix 1, and the sixth instance of "a legitimate volume
// decline gets auto-blocked forever" -- this one reached through deny_ratio,
// the last remaining feature that is still a ratio. Round 5 fixed the same
// failure in tool_diversity by scoring a raw count instead; deny_ratio
// cannot do that without losing genuine small-absolute-count proportional
// spikes, so it is gated on volume instead.
//
// Hand-traced against establishHighVolumeDenyBaseline: an identity that
// habitually gets a handful of denied probes (3-5 per 200-call window)
// records the *same 4 absolute denials it always has* in a legitimately
// quiet 20-call window. Nothing about its denial behavior changed -- only
// the denominator shrank -- yet ratio = 4/20 = 0.20 is 10x the 0.0195455
// baseline mean, and pre-fix the block-gating score was
// (0.20-0.0195455)/0.030954 = 5.83, past the 4.0 threshold. Because a
// flagged window is never folded into the baseline, that re-blocked at
// every rollover: permanent lockout.
//
// With the gate, z_rate = (20-200)/30 = -6.0 excludes deny_ratio from
// auto-block candidacy entirely, leaving only benign candidates and a block
// score floored to 0.
func TestDetector_MLScore_DenyRatioVolumeDecline_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	establishHighVolumeDenyBaseline(d, clock, "alice")

	publishMixedWindow(d, clock, "alice", 20, 4, 200*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("an unchanged absolute deny count in a quieter window must never auto-block, got %+v", blocker.calls)
	}
	// Guards against a vacuous pass, and pins the traced arithmetic: the
	// two-sided log score is untouched by the gate, so this window is still
	// surfaced as telemetry at (0.20-0.0195455)/0.0041560 = 43.42.
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the quiet window to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 43.42 (driving feature: deny_ratio)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// TestDetector_MLScore_DenyRatioToolCallShareCollapse_NeverBlocks is the
// regression gate for round 9: round 7 gated deny_ratio's auto-block
// candidacy on zRate >= 0 to prove "this window's volume didn't decline
// before we trust the ratio", but zRate is scored from windowCounts.total,
// which deliberately counts ALL traffic (MCP protocol-lifecycle passthrough
// and tool-less error entries included). deny_ratio's actual denominator is
// windowCounts.toolCalls. Pad total back up to the baseline with non-tool-call
// traffic while the real toolCalls collapses and that gate reads as satisfied
// while the denominator it exists to protect has shrunk -- re-opening the exact
// ratio-volume-decline artifact round 7 was built to close.
//
// Hand-traced against establishHighVolumeDenyBaseline (11 folded windows,
// denyRatio mean 0.215/11 = 0.0195455 with raw stddev 0.0041560; rate,
// diversity and toolCalls all a flat 200, so each is floored to 0.15*200 = 30):
// an identity carrying the same habitual 4 absolute denials it always has,
// in a window whose real tool calls collapsed but whose total was padded
// back to 200 by passthrough/error entries. pSmoothed is round 11's
// fixed-weight form (0.0195455*8+0.5)/(8+1) = 0.0729293, the same for both
// rows since it no longer depends on the window's own toolCalls; only se's
// own 1/sqrt(n) still does:
//
//	toolCalls | ratio | se        | zDenyBlock
//	20        | 0.20  | 0.0581423 | 3.1037
//	10        | 0.40  | 0.0822257 | 4.6281
//
// Pre-round-9 both cleared auto_block's 4.0 threshold through the zRate gate
// (4.0040 and 4.9436 under that round's toolCalls-weighted pSmoothed), since
// zRate = (200-200)/30 = 0 reads as "volume held steady". Gating on
// zToolCalls instead: (20-200)/30 = -6.0 and (10-200)/30 = -6.33, both
// negative, so deny_ratio is not an auto-block candidate at all and the
// block score floors to 0 (zRate 0, zDiversity (toolCalls-200)/30 < 0,
// -zInterArrival 0 at the baseline's own constant 200ms spacing).
//
// Deliberately distinct from TestDetector_MLScore_DenyRatioPassthroughInflatedTotal_NeverBlocks:
// that window's toolCalls is 2, *below* MLScore.MinCalls, so zDenyBlock is
// short-circuited to 0 outright and it never exercised any volume-decline
// protection. Both toolCalls counts here clear MinCalls (5) while sitting far
// below the baseline's typical 200, which is the actual gap.
func TestDetector_MLScore_DenyRatioToolCallShareCollapse_NeverBlocks(t *testing.T) {
	for _, realToolCalls := range []int{20, 10} {
		t.Run(fmt.Sprintf("%d real tool calls padded to 200 total", realToolCalls), func(t *testing.T) {
			clock := &fakeClock{t: time.Unix(0, 0)}
			writer := &recordingWriter{}
			blocker := &recordingBlocker{}
			d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

			establishHighVolumeDenyBaseline(d, clock, "alice")

			// The habitual 4 denials, unchanged -- only the denominator moved.
			publishMixedWindow(d, clock, "alice", realToolCalls, 4, 200*time.Millisecond)
			// Pad total back to the baseline's 200 with traffic that never
			// reaches deny_ratio's denominator: protocol-lifecycle passthrough
			// and tool-less error entries, the two entry kinds isToolCall
			// rejects. Alternated so neither kind alone carries the scenario.
			for i := realToolCalls; i < 200; i++ {
				e := auditdomain.Entry{Identity: "alice", Tool: "tools/list", Decision: "passthrough"}
				if i%2 == 1 {
					e = auditdomain.Entry{Identity: "alice", Tool: "", Decision: "error"}
				}
				d.Publish(e)
				clock.t = clock.t.Add(200 * time.Millisecond)
			}
			clock.t = clock.t.Add(61 * time.Second)
			d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

			if len(blocker.calls) != 0 {
				t.Errorf("an unchanged absolute deny count over a collapsed tool-call share must never auto-block, however much passthrough traffic padded total, got %+v", blocker.calls)
			}
			// Guards against a vacuous pass and pins the traced arithmetic: the
			// two-sided log score is untouched by the gate, so the window is
			// still surfaced as telemetry at (ratio-0.0195455)/0.0041560.
			logged := mlScoreAnomalies(writer)
			if len(logged) != 1 {
				t.Fatalf("expected the padded window to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
			}
			want := "combined z-score 43.42 (driving feature: deny_ratio)"
			if realToolCalls == 10 {
				want = "combined z-score 91.54 (driving feature: deny_ratio)"
			}
			if !strings.Contains(logged[0].Detail, want) {
				t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
			}
		})
	}
}

// TestDetector_MLScore_InterArrivalSlowdown_NeverBlocks covers the one
// feature whose harmful direction is *negative* z -- risk is calls arriving
// closer together, so maxHarmfulZ compares -z_interArrival. That sign flip
// is the only place the one-sided gate can be silently wrong in the
// dangerous direction, and no existing test exercises inter_arrival_time as
// a driving feature at all (every wild-burst test has a zero-variance
// inter-arrival baseline, scoring 0).
//
// 10 calls/window with spacing alternating 1.0s and 1.2s gives an 11-sample
// baseline of mean 1.0909s, raw stddev 0.1045 floored to 0.15*1.0909 =
// 0.1636. A window at 4s spacing (a client that slowed down 4x) scores
// z_interArrival = (4.0 - 1.0909) / 0.1636 = +17.78: enormous, and entirely
// benign. Sign-flipped it is -17.78, floored to 0 -- no block.
func TestDetector_MLScore_InterArrivalSlowdown_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	for i := 0; i < 11; i++ {
		spacing := time.Second
		if i%2 == 1 {
			spacing = 1200 * time.Millisecond
		}
		publishWindow(d, clock, "alice", manyToolNames(10), "allow", 10, spacing)
		clock.t = clock.t.Add(61 * time.Second)
	}

	publishWindow(d, clock, "alice", manyToolNames(10), "allow", 10, 4*time.Second)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("a client slowing down must never auto-block, got %+v", blocker.calls)
	}
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the slowdown to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 17.78 (driving feature: inter_arrival_time)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// establishSlowPacedBaseline publishes 11 windows of 20 calls over
// fixedTools at spacing alternating 2.5s/2.6s, so inter_arrival_time is the
// only feature with any variance: mean 2.545455, raw stddev 0.0522233,
// floored per minStddevRelFraction to 0.15*2.545455 = 0.381818. Call rate
// is exactly 20 in every window (zero variance, floored by zCount to
// max(0.15*20 = 3.0, sqrt(20) = 4.4721) = 4.4721) and the distinct-tool
// count exactly 5 (floored to max(0.75, sqrt(5) = 2.2361) = 2.2361).
func establishSlowPacedBaseline(d *usecase.Detector, clock *fakeClock, identity string) {
	for i := 0; i < 11; i++ {
		spacing := 2500 * time.Millisecond
		if i%2 == 1 {
			spacing = 2600 * time.Millisecond
		}
		publishWindow(d, clock, identity, fixedTools, "allow", 20, spacing)
		clock.t = clock.t.Add(61 * time.Second)
	}
}

// TestDetector_MLScore_FastPaceLowVolume_NeverBlocks is the regression gate
// for inter_arrival_time's harmful direction firing without any volume
// behind it. "Calls arriving closer together" is the burst signal, but a
// burst needs volume: an identity making *half* its usual number of calls,
// bunched into a shorter stretch, is not one -- and the one-sided gate,
// which flipped any negative zInterArrival into a positive block score
// regardless of zRate, auto-blocked it.
//
// Hand-traced against the baseline above: a window of 10 calls (half
// volume) over the same 5 tools with no denials, spaced 300ms apart, scores
// z_rate = (10-20)/max(0.15*20 = 3.0, sqrt(20) = 4.4721) = -2.236
// (correctly benign, volume declined) and
// z_interArrival = (0.3-2.545455)/0.381818 = -5.881, which sign-flips to
// +5.881 and cleared the 4.0 block threshold on its own. With the zRate >= 0
// gate the inter-arrival candidate is not considered at all, leaving only
// benign candidates and a block score floored to 0.
func TestDetector_MLScore_FastPaceLowVolume_NeverBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	establishSlowPacedBaseline(d, clock, "alice")

	publishWindow(d, clock, "alice", fixedTools, "allow", 10, 300*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	if len(blocker.calls) != 0 {
		t.Errorf("fewer calls that happen to land closer together is not a burst and must never auto-block, got %+v", blocker.calls)
	}
	// Guards against a vacuous pass: the two-sided log score must show the
	// inter-arrival signal really was there and really was large.
	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the faster pace to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 5.88 (driving feature: inter_arrival_time)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
}

// TestDetector_MLScore_FastPaceSameVolume_StillBlocks is the other half of
// the zRate >= 0 gate: at or above baseline volume, a tightening pace is a
// genuine burst and must still block. Same baseline, same 300ms spacing and
// therefore the identical z_interArrival = -5.881, but 20 calls instead of
// 10 -- z_rate = (20-20)/4.4721 = 0, which passes the gate, so the sign-flipped
// +5.881 is considered and clears the 4.0 threshold. Nothing but volume
// separates this test from the one above.
func TestDetector_MLScore_FastPaceSameVolume_StillBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	establishSlowPacedBaseline(d, clock, "alice")

	publishWindow(d, clock, "alice", fixedTools, "allow", 20, 300*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected the burst to be logged exactly once as ml_score, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 5.88 (driving feature: inter_arrival_time)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
	}
	if len(blocker.calls) != 1 {
		t.Fatalf("expected a same-volume burst to auto-block exactly once, got %d: %+v", len(blocker.calls), blocker.calls)
	}
	if !strings.Contains(blocker.calls[0].reason, "inter_arrival_time") {
		t.Errorf("expected the block reason to name inter_arrival_time, got %q", blocker.calls[0].reason)
	}
}

// fixedTools is a small, unchanging tool set -- the window shape every
// pre-existing ml_score test lacked. manyToolNames(n) hands a window n
// distinct names for n calls, which pins the distinct-tool count to the
// call count; separating the two is the only way a test can tell a
// distinct-tool *count* apart from a distinct/total *ratio*.
var fixedTools = []string{"read_file", "list_dir", "write_file", "search_code", "stat_file"}

// establishFixedToolSetBaseline publishes 11 windows of 90/100/110 calls
// over fixedTools, so call rate has real variance (mean 99.0909, raw
// stddev 8.3121, floored per minStddevRelFraction to 0.15*99.0909 =
// 14.8636) while the distinct-tool count is a flat 5 in every one. 11
// published windows leave 10 folded; the caller's own next window folds
// the 11th, so whatever the caller publishes next is scored against an
// 11-sample baseline. 200ms spacing keeps a 110-call window inside its own
// 60s boundary, and being constant it holds inter-arrival at zero variance.
func establishFixedToolSetBaseline(d *usecase.Detector, clock *fakeClock, identity string) {
	for _, n := range []int{90, 100, 110, 90, 100, 110, 90, 100, 110, 90, 100} {
		publishWindow(d, clock, identity, fixedTools, "allow", n, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
	}
}

// TestDetector_MLScore_VolumeDeclineFixedToolSet_NeverBlocks is the
// regression gate for the fifth instance of "a legitimate decline gets
// auto-blocked forever" -- this one reached through tool_diversity instead
// of call_rate, because that feature used to be the ratio
// distinct-tools/total-calls. Holding the tool set fixed and only dropping
// volume *raises* such a ratio, which is exactly maxHarmfulZ's
// rising-diversity direction, so the one-sided gate that closed this
// failure for call_rate and deny_ratio let it back in here. Against the
// 11-sample baseline above the old ratio (mean 0.050781, floored stddev
// 0.0076171) scored z_diversity = (5/60 - 0.050781)/0.0076171 = +4.27 for
// the 40% decline and (5/20 - 0.050781)/0.0076171 = +26.16 for the
// truncated window -- both past auto_block's 4.0. And since the two-sided
// score also cleared the 3.0 log threshold, neither window was ever folded
// into the baseline, so the block re-fired at every rollover forever.
//
// Scoring the raw distinct-tool count instead makes the feature
// volume-invariant: 5 tools is 5 tools whether they appear over 110 calls
// or 20, so z_diversity is 0 in both sub-cases below and call_rate -- whose
// decline is benign by maxHarmfulZ's definition -- is all that is left.
func TestDetector_MLScore_VolumeDeclineFixedToolSet_NeverBlocks(t *testing.T) {
	// A 40% volume drop: z_rate = (60 - 99.0909)/14.8636 = -2.63, which
	// doesn't even clear the 3.0 log threshold, so this window is folded and
	// the baseline adapts to the quieter regime rather than fighting it.
	t.Run("40 percent volume decline", func(t *testing.T) {
		clock := &fakeClock{t: time.Unix(0, 0)}
		writer := &recordingWriter{}
		blocker := &recordingBlocker{}
		d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

		establishFixedToolSetBaseline(d, clock, "alice")
		publishWindow(d, clock, "alice", fixedTools, "allow", 60, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

		if len(blocker.calls) != 0 {
			t.Errorf("a volume decline over an unchanged tool set must never auto-block, got %+v", blocker.calls)
		}
		if logged := mlScoreAnomalies(writer); len(logged) != 0 {
			t.Errorf("expected a 2.63-scoring window to fall below the 3.0 log threshold entirely, got %+v", logged)
		}
	})

	// An identity returning from idle: the window is truncated to 20 calls
	// over the same 5 tools. z_rate = (20 - 99.0909)/14.8636 = -5.32, so
	// unlike the sub-case above this one IS logged -- which is what keeps
	// this test honest: a baseline that silently failed to establish would
	// score every feature 0 and report zero Block calls vacuously.
	t.Run("return from idle truncates the window", func(t *testing.T) {
		clock := &fakeClock{t: time.Unix(0, 0)}
		writer := &recordingWriter{}
		blocker := &recordingBlocker{}
		d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

		establishFixedToolSetBaseline(d, clock, "alice")
		publishWindow(d, clock, "alice", fixedTools, "allow", 20, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

		if len(blocker.calls) != 0 {
			t.Errorf("a truncated return-from-idle window must never auto-block, got %+v", blocker.calls)
		}
		logged := mlScoreAnomalies(writer)
		if len(logged) != 1 {
			t.Fatalf("expected the truncated window to still be logged exactly once as ml_score telemetry, got %d: %+v", len(logged), writer.anomalies)
		}
		if want := "combined z-score 5.32 (driving feature: call_rate)"; !strings.Contains(logged[0].Detail, want) {
			t.Errorf("expected the logged two-sided score to be %q, got %q", want, logged[0].Detail)
		}
	})
}

// TestDetector_MLScore_ToolEnumeration_StillBlocks is the other half of the
// raw-count change: making tool_diversity volume-invariant must not neuter
// it. Call volume is held at a constant 100 across every window (zero
// variance, so z_rate is 0 and cannot contribute), while the distinct-tool
// count cycles 4/5/6 -- mean 4.9091, raw stddev 0.8312, above the
// 0.15*4.9091 = 0.7364 relative floor. zCount's count floor is what binds
// here instead: max(0.7364, 0.8312, sqrt(4.9091) = 2.2156) = 2.2156, since a
// baseline this tight is exactly the small-integer zone where a divisor below
// the feature's own Poisson-like sampling noise turns ordinary variation into
// a multi-sigma event. A window that keeps the same 100 calls but spreads
// them over 40 distinct tools therefore scores
// z_diversity = (40 - 4.9091)/2.2156 = +15.84: genuine enumeration, the only
// thing a raw count still moves on, and it must both log and block. The floor
// costs this case 19.25 of a 35.09 unfloored score (round 10's flat 1.0 floor
// cost 7.13 of it) and nothing at all of the outcome -- still ~4x the 4.0
// block threshold. Note the volume is identical to the baseline's, so nothing
// but diversity could have produced this score.
func TestDetector_MLScore_ToolEnumeration_StillBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	for _, distinct := range []int{4, 5, 6, 4, 5, 6, 4, 5, 6, 4, 5} {
		publishWindow(d, clock, "alice", manyToolNames(distinct), "allow", 100, 200*time.Millisecond)
		clock.t = clock.t.Add(61 * time.Second)
	}

	publishWindow(d, clock, "alice", manyToolNames(40), "allow", 100, 200*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected tool enumeration to be logged exactly once as ml_score, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 15.84 (driving feature: tool_diversity)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected tool_diversity to drive the logged score as %q, got %q", want, logged[0].Detail)
	}
	if len(blocker.calls) != 1 {
		t.Fatalf("expected tool enumeration to auto-block exactly once, got %d: %+v", len(blocker.calls), blocker.calls)
	}
	if !strings.Contains(blocker.calls[0].reason, "tool_diversity") {
		t.Errorf("expected the block reason to name tool_diversity, got %q", blocker.calls[0].reason)
	}
}

// TestDetector_MLScore_ToolEnumeration_ZeroVarianceBaseline_StillBlocks is
// the Detector-level regression gate for onlineStat.ZScore's zero-variance
// short-circuit, which returned 0 before the relative-stddev floor was
// ever applied. establishFixedToolSetBaseline's 11 windows all touch
// exactly the same 5 tools, so the distinct-tool count has raw variance
// *exactly* 0 -- the tightest baseline possible, and previously the one
// baseline shape from which no deviation could ever be detected. That made
// the raw-count diversity fix incomplete: TestDetector_MLScore_ToolEnumeration_StillBlocks
// above builds its baseline from a 4/5/6 cycle, which has real variance and
// so never reached the short-circuit at all.
//
// Hand-traced: diversity mean 5 with zero variance. The relative floor
// gives 0.15*5 = 0.75, but zCount's count floor is larger and therefore
// binds: max(0.75, sqrt(5) = 2.2361) = 2.2361 -- a mean of 5 distinct tools
// is squarely in the small-integer zone where three quarters of a tool is not
// a meaningful unit of deviation, and even one whole tool (round 10's flat
// floor) sits under this count's own sqrt(5) sampling noise. A window
// spreading 100 calls (the baseline's own volume range, so call_rate
// contributes essentially nothing: z_rate = (100-99.0909)/14.8636 = 0.06 --
// mean 99.0909 is the one place the relative floor 14.8636 still exceeds
// sqrt(99.0909) = 9.95) over 60 distinct tools scores
// z_diversity = (60-5)/2.2361 = 24.60. Pre-round-6 that was 0 and this
// blatant enumeration sweep did not even clear the 3.0 log threshold; the
// floors move it from 73.33 unfloored to 55.00 (round 10) to 24.60 (round
// 11), i.e. still ~6x the 4.0 block threshold, so they cost the magnitude
// and not the outcome.
func TestDetector_MLScore_ToolEnumeration_ZeroVarianceBaseline_StillBlocks(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := &recordingBlocker{}
	d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

	establishFixedToolSetBaseline(d, clock, "alice")

	publishWindow(d, clock, "alice", manyToolNames(60), "allow", 100, 200*time.Millisecond)
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})

	logged := mlScoreAnomalies(writer)
	if len(logged) != 1 {
		t.Fatalf("expected enumeration against a zero-variance diversity baseline to be logged exactly once, got %d: %+v", len(logged), writer.anomalies)
	}
	if want := "combined z-score 24.60 (driving feature: tool_diversity)"; !strings.Contains(logged[0].Detail, want) {
		t.Errorf("expected the logged score to be %q, got %q", want, logged[0].Detail)
	}
	if len(blocker.calls) != 1 {
		t.Fatalf("expected enumeration against a zero-variance diversity baseline to auto-block exactly once, got %d: %+v", len(blocker.calls), blocker.calls)
	}
	if !strings.Contains(blocker.calls[0].reason, "tool_diversity") {
		t.Errorf("expected the block reason to name tool_diversity, got %q", blocker.calls[0].reason)
	}
}

// TestDetector_MLScore_DiversitySmallIntegerChange_NeverBlocks is the
// regression gate for round 10, the seventh instance of "legitimate traffic
// gets auto-blocked forever" and the second of "a floor that doesn't
// actually floor anything meaningful" (round 6 closed the first, for zero
// variance). tool_diversity is an integer count of distinct tools, and
// minStddevRelFraction alone floors its divisor at 0.15*mean -- which for a
// small baseline mean is *smaller than one whole tool*, the smallest unit
// the feature can move by at all. An identity that habitually touches
// exactly one tool per window therefore scored the smallest possible real
// change -- one additional distinct tool, same volume, same spacing, same
// everything else -- at z_diversity = (2-1)/(0.15*1) = 6.67, past both the
// shipped example config's 3.0 log threshold and its 4.0 block threshold.
// And because a flagged window is never folded, the baseline stayed pinned
// at mean 1 and the block re-fired at every rollover: an indefinite lockout
// for an identity whose behavior never changed beyond touching one more
// tool than usual.
//
// Hand-traced with zCount's count floor against this test's own baseline:
// diversity is a constant 1 across 11 folded windows (mean 1, zero
// variance), so the divisor is max(0.15*1, 0, sqrt(1) = 1.0) = 1.0 -- mean 1
// is the one point where round 11's sqrt(mean) floor and round 10's flat 1.0
// coincide exactly, so this test's own numbers are unchanged by round 11 --
// and the +1-tool window scores z_diversity = (2-1)/1.0 = 1.00, below even
// the 3.0 log threshold, a 4x margin under the block threshold. Every other
// feature is pinned flat by construction: volume is exactly 20 calls in
// every window including this one, so
// z_rate = (20-20)/max(0.15*20, sqrt(20)) = 0; spacing is a flat 1s, so
// z_interArrival = 0; there are no denials, so z_deny = 0 and
// zDenyBlock = (0-0)/se = 0. Diversity is the only feature that moved at
// all, which is what makes this a clean isolation of the reported failure.
//
// The mean-1 case is asserted rather than the mean-5 -> 9 case from the
// same family because under round 10's flat 1.0 floor that one landed on
// exactly (9-5)/1.0 = 4.00. That did not block -- the auto-block gate is a
// strict `>` -- but an assertion sitting exactly on the threshold is a coin
// flip dressed up as a test, the same thin-margin problem rounds 6 and 8
// corrected in their own cases. Round 11's floor resolves that case outright
// rather than leaving it on the boundary: (9-5)/max(0.75, sqrt(5) = 2.2361)
// = 1.79, which no longer even clears the 3.0 log threshold.
//
// The paired subtest is what stops the floor from being a free pass, and
// what keeps the first subtest from passing vacuously: a baseline that
// silently failed to establish would score every feature 0 and report zero
// Block calls too, so the same helper is reused to prove the baseline is
// real and that low-end enumeration still blocks through it.
func TestDetector_MLScore_DiversitySmallIntegerChange_NeverBlocks(t *testing.T) {
	// 11 windows of 20 calls all to the same single tool: diversity a
	// constant 1, call rate a constant 20, spacing a constant 1s, no denies.
	// 11 published windows leave 10 folded; the caller's own next window
	// folds the 11th, so whatever the caller publishes next is scored
	// against an 11-sample baseline -- comfortably past minSamplesForZScore
	// (8), matching the shape every other baseline helper in this file uses.
	establishSingleToolBaseline := func(d *usecase.Detector, clock *fakeClock) {
		for i := 0; i < 11; i++ {
			publishWindow(d, clock, "alice", []string{"read_file"}, "allow", 20, time.Second)
			clock.t = clock.t.Add(61 * time.Second)
		}
	}
	rollWindow := func(d *usecase.Detector, clock *fakeClock) {
		clock.t = clock.t.Add(61 * time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"})
	}

	// The reported false positive itself: the smallest change the feature
	// can express. 19 of the same habitual calls plus exactly one call to a
	// second tool -- volume, spacing and deny count all identical to every
	// baseline window, so diversity 1 -> 2 is the only difference there is.
	t.Run("exactly one additional distinct tool", func(t *testing.T) {
		clock := &fakeClock{t: time.Unix(0, 0)}
		writer := &recordingWriter{}
		blocker := &recordingBlocker{}
		d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

		establishSingleToolBaseline(d, clock)

		publishWindow(d, clock, "alice", []string{"read_file"}, "allow", 19, time.Second)
		d.Publish(auditdomain.Entry{Identity: "alice", Tool: "list_dir", Decision: "allow"})
		clock.t = clock.t.Add(time.Second)
		rollWindow(d, clock)

		if len(blocker.calls) != 0 {
			t.Errorf("one additional distinct tool over an identity's habitual single-tool baseline must never auto-block, got %+v", blocker.calls)
		}
		if logged := mlScoreAnomalies(writer); len(logged) != 0 {
			t.Errorf("expected a 1.00-scoring window to fall below the 3.0 log threshold entirely, got %+v", logged)
		}
	})

	// The other half: the 1.0 floor must suppress the single-quantum noise
	// case only, not detection at the low end generally. Same baseline, same
	// 20 calls, same 1s spacing -- but spread over 12 distinct tools, so
	// z_diversity = (12-1)/1.0 = 11.00, still ~3x the block threshold. This
	// is the case that would be lost if the floor were set by call volume
	// rather than by one whole tool.
	t.Run("small-scale enumeration still blocks", func(t *testing.T) {
		clock := &fakeClock{t: time.Unix(0, 0)}
		writer := &recordingWriter{}
		blocker := &recordingBlocker{}
		d := usecase.NewDetector(declineCfg(), writer, nil, blocker, nil, clock.now)

		establishSingleToolBaseline(d, clock)

		publishWindow(d, clock, "alice", manyToolNames(12), "allow", 20, time.Second)
		rollWindow(d, clock)

		logged := mlScoreAnomalies(writer)
		if len(logged) != 1 {
			t.Fatalf("expected low-end enumeration to be logged exactly once as ml_score, got %d: %+v", len(logged), writer.anomalies)
		}
		if want := "combined z-score 11.00 (driving feature: tool_diversity)"; !strings.Contains(logged[0].Detail, want) {
			t.Errorf("expected tool_diversity to drive the logged score as %q, got %q", want, logged[0].Detail)
		}
		if len(blocker.calls) != 1 {
			t.Fatalf("expected low-end enumeration to auto-block exactly once, got %d: %+v", len(blocker.calls), blocker.calls)
		}
		// Pins the block-gating score, not just the feature name: the claim
		// here is that the margin above 4.0 is real, which "names
		// tool_diversity" would satisfy just as happily at 4.01.
		if want := "ml_score 11.00 (feature: tool_diversity)"; !strings.Contains(blocker.calls[0].reason, want) {
			t.Errorf("expected the block reason to be %q, got %q", want, blocker.calls[0].reason)
		}
	})
}
