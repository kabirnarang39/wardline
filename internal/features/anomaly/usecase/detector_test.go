package usecase_test

import (
	"fmt"
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
// ordinary 50% swing. diversity/deny-ratio/inter-arrival are held
// constant (unique tool per call, no denies, fixed 1s spacing, and
// lastCallAt resetting every rollover keeps that spacing honest) so this
// isolates exactly the rate dimension the false positive fired on.
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

// TestDetector_MLScore_OrdinaryGrowth_NeverFlags is the end-to-end
// (Detector-level) regression gate for the remainder of N1: the reviewer's
// exact repro, driven through Publish rather than onlineStat directly.
// Baseline {10, 11} alternating x8 gives mean 10.5 and sample stddev
// 0.5345; a following window of 13 calls is a 24% increase -- ordinary
// traffic variation. Unfloored that scores z = (13-10.5)/0.5345 = 4.68,
// which clears BOTH thresholds below: it would log an anomaly and
// auto-block the identity. With minStddevRelFraction the divisor is
// floored at 0.15*10.5 = 1.575 and the same window scores 1.59.
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

	// One distinct tool per call and a fixed 1s spacing hold diversity at a
	// constant 1.0 and mean inter-arrival at a constant 1s, so those two
	// features have zero variance (ZScore 0) and this test isolates rate.
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
	// sample stddev sqrt(8/7) = 1.069); diversity/deny-ratio/inter-arrival
	// held constant (unique tool per call, no denies, fixed 1s spacing) so
	// only rate varies.
	baseRates := []int{10, 12, 10, 12, 10, 12, 10, 12}
	for _, n := range baseRates {
		publishWindow(d, clock, "alice", manyToolNames(n), "allow", n, time.Second)
		clock.t = clock.t.Add(61 * time.Second)
	}

	// Target window: rate 20. minStddevRelFraction floors the divisor at
	// 0.15*11 = 1.65 (above the real 1.069), so z = (20-11)/1.65 = 5.45 --
	// real margin on both sides of the 3.0 log threshold and the 8.0 block
	// threshold. Picked deliberately: the rate of 16 this test used before
	// the relative-stddev floor scored 3.03 against the floored divisor,
	// clearing the 3.0 log threshold by 0.03 and making the test's own
	// premise a coin flip.
	publishWindow(d, clock, "alice", manyToolNames(20), "allow", 20, time.Second)
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
