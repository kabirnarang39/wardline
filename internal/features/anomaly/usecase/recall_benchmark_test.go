package usecase_test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// This file measures the shipped ml_score/auto_block detector's actual
// recall against a battery of adversarial traffic shapes, and its false
// positive rate across more seeds than
// TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic's single one --
// not unit-test pass/fail on a single scenario, but a real, reproducible
// number per attack shape. Every scenario runs against the exact
// shipped-example config from the README/docs (ml_score threshold 3.0,
// auto_block threshold 8.0), the real Detector and BlockChecker, no
// mocks of the scoring logic itself. Run with:
//
//	go test ./internal/features/anomaly/usecase/ -run TestRecallBenchmark -v
//
// Numbers logged here are what docs/features/anomaly-detection.md's
// benchmark section reports -- if this file's scenarios or config
// change, that section is now stale and needs updating alongside it.

// shippedExampleCfg mirrors the exact anomaly: block in the README and
// docs/features/anomaly-detection.md's shipped example -- this benchmark
// measures what an operator who pastes that example actually gets, not
// an arbitrary test-tuned threshold.
func shippedExampleCfg() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds:        60,
		RateSpikeEnabled:     true,
		RateMultiplier:       5,
		RateMinCalls:         10,
		NovelToolEnabled:     true,
		DenyRateSpikeEnabled: true,
		DenyRateThreshold:    0.5,
		DenyRateMinCalls:     10,
		MLScore:              domain.MLScoreConfig{Enabled: true, ScoreThreshold: 3.0, MinCalls: 5},
		AutoBlock:            domain.AutoBlockConfig{Enabled: true, ScoreThreshold: 8.0, BlockDurationSeconds: 300},
	}
}

var benchTools = []string{"read_file", "list_dir", "stat", "search", "grep", "diff"}

// warmDetector runs warmupWindows windows of ordinary ~baseline calls/
// window (±20% jitter) for identity, against a fresh Detector/BlockChecker
// pair, so every scenario below starts from the same kind of established
// baseline a real long-running identity would have -- not a cold,
// unscored first window.
func warmDetector(t *testing.T, rng *rand.Rand, cfg domain.HeuristicConfig, identity string, baseline, warmupWindows int) (*usecase.Detector, *usecase.BlockChecker, *fakeClock, *recordingWriter) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, writer, nil, blocker, nil, clock.now, nil)

	jitter := baseline / 5
	if jitter < 1 {
		jitter = 1
	}
	for w := 0; w < warmupWindows; w++ {
		calls := baseline - jitter + rng.Intn(2*jitter+1)
		for c := 0; c < calls; c++ {
			d.Publish(auditdomain.Entry{Identity: identity, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}
	return d, blocker, clock, writer
}

// scoreWindow publishes calls entries as one window's traffic, advances
// the clock past the window boundary, then publishes one extra "probe"
// entry in the new window.
//
// The probe is not decoration -- Detector.recordAndCheck only scores a
// completed window (moves it from st.cur to st.prev and runs
// checkMLScore) when the FIRST entry of the FOLLOWING window arrives; a
// window that's merely advanced past by the clock, with no further
// Publish call, is never scored at all. evasion_test.go's own
// TestDetector_AutoBlock_AbruptSpikeIsBlocked hits this exact requirement
// ("one more call in the next window forces the spike window to complete
// and be evaluated") for the same reason: a single-shot attack window,
// unlike a ramp loop's own next iteration, has no later Publish call to
// serve as that trigger unless one is added explicitly.
//
// The probe is inert by construction: min_calls on every heuristic that
// gates on total volume (RateMinCalls, DenyRateMinCalls,
// MLScore.MinCalls) is >= 5 in the shipped-example config, so a
// 1-call window neither scores nor folds into any baseline itself --
// verified directly against checkMLScore/checkRateSpike/
// checkDenyRateSpike's own MinCalls gates, not assumed.
func scoreWindow(d *usecase.Detector, clock *fakeClock, cfg domain.HeuristicConfig, identity string, calls int, tool string, decision string) {
	for c := 0; c < calls; c++ {
		d.Publish(auditdomain.Entry{Identity: identity, Tool: tool, Decision: decision})
	}
	clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	d.Publish(auditdomain.Entry{Identity: identity, Tool: "__probe__", Decision: "allow"})
}

// TestRecallBenchmark_AbruptSpike measures, per spike multiple (relative
// to a ~30 calls/window baseline), what fraction of independent trials
// get auto-blocked -- the "how obvious does an attack have to be" curve
// for the flagship claim (README: "blocks a compromised agent in real
// time").
func TestRecallBenchmark_AbruptSpike(t *testing.T) {
	cfg := shippedExampleCfg()
	const baseline = 30
	const trialsPerMultiple = 20
	multiples := []float64{1.5, 2, 3, 5, 10, 20}

	t.Log("abrupt-spike recall (single-window spike after 20-window warmup, 20 trials/multiple):")
	for _, mult := range multiples {
		blocked := 0
		for trial := 0; trial < trialsPerMultiple; trial++ {
			rng := rand.New(rand.NewSource(int64(trial)*1000 + int64(mult*10)))
			identity := fmt.Sprintf("spike-%v-%d", mult, trial)
			d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

			spikeCalls := int(float64(baseline) * mult)
			scoreWindow(d, clock, cfg, identity, spikeCalls, benchTools[rng.Intn(len(benchTools))], "allow")

			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blocked++
			}
		}
		recall := float64(blocked) / float64(trialsPerMultiple)
		t.Logf("  %5.1fx baseline: %2d/%d blocked (%.0f%% recall)", mult, blocked, trialsPerMultiple, recall*100)
	}
}

// TestRecallBenchmark_LowAndSlow quantifies the documented low-and-slow
// blind spot (docs/features/anomaly-detection.md "Known limitations"):
// per ramp rate, whether auto_block ever fires within 150 windows, and
// if not, the highest multiple of the original baseline the identity
// reaches while still unblocked -- the actual size of the blind spot,
// not just "it exists."
func TestRecallBenchmark_LowAndSlow(t *testing.T) {
	cfg := shippedExampleCfg()
	const baseline = 30
	const maxWindows = 150
	ramps := []int{1, 2, 3, 5, 10}

	t.Log("low-and-slow recall (ramp rate = +N calls/window after 20-window warmup, 150-window ceiling):")
	for _, ramp := range ramps {
		rng := rand.New(rand.NewSource(int64(ramp) * 7919))
		identity := fmt.Sprintf("creeper-%d", ramp)
		d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

		calls := baseline
		blockedAtWindow := -1
		for w := 0; w < maxWindows; w++ {
			calls += ramp
			scoreWindow(d, clock, cfg, identity, calls, benchTools[rng.Intn(len(benchTools))], "allow")
			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blockedAtWindow = w
				break
			}
		}
		finalMultiple := float64(calls) / float64(baseline)
		if blockedAtWindow >= 0 {
			t.Logf("  +%2d calls/window: blocked at window %3d (reached %.1fx baseline)", ramp, blockedAtWindow, finalMultiple)
		} else {
			t.Logf("  +%2d calls/window: NEVER blocked in %d windows (reached %.1fx baseline, %d calls/window)", ramp, maxWindows, finalMultiple, calls)
		}
	}
}

// TestRecallBenchmark_DenyRateSpike measures recall against a sudden
// spike in the identity's own deny ratio (e.g. an agent probing for
// tools policy rejects) -- both the always-on deny_rate_spike heuristic
// and ml_score's deny_ratio feature can fire on this shape, so this
// reports whether the window was flagged at all (either heuristic) and
// separately whether it was auto-blocked (ml_score/auto_block only --
// deny_rate_spike itself never blocks, see docs).
func TestRecallBenchmark_DenyRateSpike(t *testing.T) {
	cfg := shippedExampleCfg()
	const baseline = 30
	const trialsPerRate = 20
	denyRates := []float64{0.2, 0.4, 0.6, 0.8, 1.0}

	t.Log("deny-rate-spike recall (single-window deny ratio after 20-window warmup, 20 trials/rate):")
	for _, rate := range denyRates {
		flagged, blocked := 0, 0
		for trial := 0; trial < trialsPerRate; trial++ {
			rng := rand.New(rand.NewSource(int64(trial)*1000 + int64(rate*100)))
			identity := fmt.Sprintf("denier-%v-%d", rate, trial)
			d, blocker, clock, writer := warmDetector(t, rng, cfg, identity, baseline, 20)

			before := len(writer.anomalies)
			denyCalls := int(float64(baseline) * rate)
			allowCalls := baseline - denyCalls
			for c := 0; c < denyCalls; c++ {
				d.Publish(auditdomain.Entry{Identity: identity, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "deny"})
			}
			for c := 0; c < allowCalls; c++ {
				d.Publish(auditdomain.Entry{Identity: identity, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
			}
			// deny_rate_spike is checked per-call, in-window -- it has
			// already fired (or not) by this point, so "flagged" is read
			// before the probe below. ml_score's window score has NOT been
			// computed yet (see scoreWindow's doc comment); the probe is
			// what forces that, for the "blocked" measurement right after.
			if len(writer.anomalies) > before {
				flagged++
			}
			clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
			d.Publish(auditdomain.Entry{Identity: identity, Tool: "__probe__", Decision: "allow"})

			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blocked++
			}
		}
		t.Logf("  %3.0f%% deny ratio: %2d/%d flagged, %2d/%d auto-blocked",
			rate*100, flagged, trialsPerRate, blocked, trialsPerRate)
	}
}

// TestRecallBenchmark_NovelToolEnumeration measures recall against a
// burst of first-ever-seen tools in one window -- the shape a scanning
// agent probing for available tools produces. novel_tool logs on the
// very first such call unconditionally; this measures whether the burst
// also crosses ml_score's tool_diversity feature far enough to
// auto-block.
func TestRecallBenchmark_NovelToolEnumeration(t *testing.T) {
	cfg := shippedExampleCfg()
	const baseline = 30
	const trialsPerBurst = 20
	burstSizes := []int{2, 5, 10, 20, 40}

	t.Log("novel-tool-enumeration recall (single-window burst of brand-new distinct tools, 20 trials/size):")
	for _, burst := range burstSizes {
		blocked := 0
		for trial := 0; trial < trialsPerBurst; trial++ {
			rng := rand.New(rand.NewSource(int64(trial)*1000 + int64(burst)))
			identity := fmt.Sprintf("scanner-%d-%d", burst, trial)
			d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

			for c := 0; c < burst; c++ {
				d.Publish(auditdomain.Entry{Identity: identity, Tool: fmt.Sprintf("tool_%d_%d", trial, c), Decision: "allow"})
			}
			clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
			d.Publish(auditdomain.Entry{Identity: identity, Tool: "__probe__", Decision: "allow"})

			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blocked++
			}
		}
		recall := float64(blocked) / float64(trialsPerBurst)
		t.Logf("  %2d new tools in one window: %2d/%d blocked (%.0f%% recall)", burst, blocked, trialsPerBurst, recall*100)
	}
}

// TestRecallBenchmark_FalsePositiveRateAcrossSeeds broadens
// TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic's single seed=1
// run to 20 independent identities/seeds, so the reported false-positive
// rate is a real average with visible per-seed spread, not one sample.
//
// Uses a 20-window warmDetector warmup, same as every other scenario in
// this file -- NOT "no separate warmup" as an earlier version of this
// test had it. Without warmup, every one of benchTools' 6 tools gets
// called for the first time inside the measured window itself, and
// novel_tool logs on every first sighting by design (see
// checkNovelTool): that is 6 deterministic, by-design log entries per
// cold-started identity, not 6 false positives, and it happened
// identically across all 20 seeds precisely because ~30 random draws
// from a 6-tool set reaches full coverage almost every time regardless
// of seed -- a first, wrong run of this test logged that as "2.000%
// false-positive rate, worst seed 2.000%," which is what an
// impossible-looking zero-variance-across-seeds result should always
// prompt: re-derive the mechanism, don't publish the number. Warming up
// first spends novel_tool's one-time signal before the measured window
// starts, so what's counted here is what TestDetector_..._SteadyTraffic
// counts too, plus rate_spike/deny_rate_spike (both configured, both
// correctly silent on ±20% jitter well under their multiplier/ratio
// thresholds).
func TestRecallBenchmark_FalsePositiveRateAcrossSeeds(t *testing.T) {
	cfg := shippedExampleCfg()
	const windows = 300
	const seeds = 20

	totalWindows, totalFP := 0, 0
	worstSeedRate := 0.0
	for seed := 0; seed < seeds; seed++ {
		rng := rand.New(rand.NewSource(int64(seed)))
		identity := fmt.Sprintf("steady-%d", seed)
		d, _, clock, writer := warmDetector(t, rng, cfg, identity, 30, 20)
		before := len(writer.anomalies) // warmup itself spends novel_tool's one-time-per-tool signal; don't count it

		for w := 0; w < windows; w++ {
			calls := 24 + rng.Intn(13) // 24..36, mean ~30, matches the existing single-seed test
			for c := 0; c < calls; c++ {
				d.Publish(auditdomain.Entry{Identity: identity, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
			}
			clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
		}
		seedFP := len(writer.anomalies) - before
		rate := float64(seedFP) / float64(windows)
		t.Logf("  seed %2d: %d/%d windows flagged (%.3f%%)", seed, seedFP, windows, rate*100)
		if rate > worstSeedRate {
			worstSeedRate = rate
		}
		totalWindows += windows
		totalFP += seedFP
	}
	overall := float64(totalFP) / float64(totalWindows)
	t.Logf("false-positive rate across %d seeds, %d windows each: %d/%d windows flagged (%.3f%% overall, %.3f%% worst single seed)",
		seeds, windows, totalFP, totalWindows, overall*100, worstSeedRate*100)
	if overall > 0.02 {
		t.Errorf("aggregate false-positive rate %.3f%% exceeds the README's 2%% budget across %d seeds", overall*100, seeds)
	}
}
