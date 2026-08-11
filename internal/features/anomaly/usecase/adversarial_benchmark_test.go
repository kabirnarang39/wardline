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

// This file goes past recall_benchmark_test.go's per-shape severity
// curves into adversarial attack SHAPES specifically constructed to
// probe the detector's own architecture, not just its thresholds --
// what a real attacker who has read this exact open-source
// implementation (every threshold, every formula, is public) could
// construct. Real findings here are reported honestly whether they
// favor the detector or not -- an evasion that succeeds is exactly as
// important to publish as a detection that succeeds; this benchmark
// exists to find the true boundary, not to make the number look good.
//
// Run with:
//
//	go test ./internal/features/anomaly/usecase/ -run TestAdversarialBenchmark -v

// TestAdversarialBenchmark_DistributedSybil tests the architecture's
// most fundamental limitation, not a tunable threshold: every heuristic
// in this package baselines per (tenant, identity). An attacker who
// controls N identities, each individually staying under every
// per-identity threshold, is invisible to all of them by construction --
// no amount of K/H/threshold tuning closes this, because the detector
// never looks across identities at all (federation correlates alert
// *counts* across instances, not raw call history across identities --
// see docs/features/anomaly-detection.md's "Known limitations").
//
// This runs 20 independent identities, each individually performing the
// exact 1.5x-baseline abrupt spike TestRecallBenchmark_AbruptSpike (and
// its drift_detection counterpart) both measured at 0% individual
// recall -- 1.5x, not 2x, deliberately: an unplanned finding while
// first building this test showed drift_detection lifts 2x-baseline
// recall to 55% (a single elevated window can push an already-nonzero
// CUSUM residual over H -- see
// TestRecallBenchmark_AbruptSpike_WithDriftDetection), which would
// confound this test's actual point. 1.5x stays confirmed at 0% recall
// even with drift_detection on, so this demonstrates the architectural
// limitation cleanly: not "the threshold happened to be too high," but
// "no per-identity heuristic, at any severity below its own threshold,
// has any way to know about the other 19 identities at all."
func TestAdversarialBenchmark_DistributedSybil(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	const baseline = 30
	const identities = 20
	const spikeMultiple = 1.5

	blockedCount := 0
	totalSpikeCalls := 0
	for i := 0; i < identities; i++ {
		rng := rand.New(rand.NewSource(int64(i) * 104729))
		identity := fmt.Sprintf("sybil-%d", i)
		d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

		spikeCalls := int(float64(baseline) * spikeMultiple)
		scoreWindow(d, clock, cfg, identity, spikeCalls, benchTools[rng.Intn(len(benchTools))], "allow")
		totalSpikeCalls += spikeCalls

		if v := blocker.Check(identity, "", clock.t); !v.Allowed {
			blockedCount++
		}
	}
	t.Logf("distributed sybil: %d/%d individual identities blocked at %.1fx baseline each; aggregate attack volume %d calls in one window across identities, entirely unseen as a single event by any per-identity heuristic (ml_score+auto_block+drift_detection all on)",
		blockedCount, identities, spikeMultiple, totalSpikeCalls)
	if blockedCount > 0 {
		t.Errorf("expected 0/%d blocked at %.1fx (the confirmed-0%%-recall multiple even with drift_detection on) -- got %d/%d; re-verify against TestRecallBenchmark_AbruptSpike_WithDriftDetection before trusting this test's own finding", identities, spikeMultiple, blockedCount, identities)
	}
}

// TestAdversarialBenchmark_MimicryCeiling asks the question a real
// attacker with this repository open in another tab would ask: every
// threshold is public (K=0.5, H=5.0, auto_block.score_threshold=8.0,
// rate_multiplier=5) -- what is the highest *sustained* (not ramping,
// not spiking -- held constant) elevated call rate that survives
// indefinitely against the full shipped config, ml_score/auto_block AND
// drift_detection both on?
//
// This is a different attack shape from both TestRecallBenchmark_AbruptSpike
// (one-shot) and TestRecallBenchmark_LowAndSlow (ever-increasing ramp):
// a plateau. A CUSUM accumulates (z-K) every window, so any sustained z
// > K climbs without bound and must eventually cross H -- there is no
// rate elevation that evades forever except one whose z-score stays at
// or below K permanently. This test sweeps candidate multiples and
// measures, for each, whether 300 windows survive -- the real answer to
// "how much room does an attacker who knows K have," not a guess.
func TestAdversarialBenchmark_MimicryCeiling(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	const baseline = 30
	const maxWindows = 300
	multiples := []float64{1.05, 1.10, 1.15, 1.20, 1.25, 1.30, 1.40, 1.50}

	t.Log("mimicry ceiling: sustained (constant, non-ramping) elevated rate, held for up to 300 windows:")
	for _, mult := range multiples {
		rng := rand.New(rand.NewSource(int64(mult * 10000)))
		identity := fmt.Sprintf("mimic-%v", mult)
		d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

		plateauCalls := int(float64(baseline) * mult)
		blockedAtWindow := -1
		for w := 0; w < maxWindows; w++ {
			scoreWindow(d, clock, cfg, identity, plateauCalls, benchTools[rng.Intn(len(benchTools))], "allow")
			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blockedAtWindow = w
				break
			}
		}
		if blockedAtWindow >= 0 {
			t.Logf("  %.2fx baseline, sustained: blocked at window %d", mult, blockedAtWindow)
		} else {
			t.Logf("  %.2fx baseline, sustained: survived all %d windows unblocked", mult, maxWindows)
		}
	}
}

// TestAdversarialBenchmark_BurstPauseDutyCycle tests whether alternating
// a high-volume window with a quiet (baseline) window defeats detection
// by exploiting two per-window reset behaviors: rate_spike/ml_score's
// flaggedThisWindow latch clears every window rotation, and CUSUM's own
// accumulator resets to 0 on any window scoring at or below the K
// allowance (see checkDrift's doc comment) -- a quiet window after a
// burst is exactly a below-allowance window. If pausing every other
// window resets the accumulator before it reaches H, this could hold a
// higher *average* elevated rate than the sustained-plateau ceiling
// above while still evading.
func TestAdversarialBenchmark_BurstPauseDutyCycle(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	const baseline = 30
	const maxCycles = 100
	burstMultiples := []float64{3, 5, 10}

	t.Log("burst-pause duty cycle: 1 high-volume window + 1 quiet (baseline) window, repeating, up to 100 cycles:")
	for _, mult := range burstMultiples {
		rng := rand.New(rand.NewSource(int64(mult) * 999983))
		identity := fmt.Sprintf("dutycycle-%v", mult)
		d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

		burstCalls := int(float64(baseline) * mult)
		blockedAtCycle := -1
		for c := 0; c < maxCycles; c++ {
			scoreWindow(d, clock, cfg, identity, burstCalls, benchTools[rng.Intn(len(benchTools))], "allow")
			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blockedAtCycle = c
				break
			}
			scoreWindow(d, clock, cfg, identity, baseline, benchTools[rng.Intn(len(benchTools))], "allow")
			if v := blocker.Check(identity, "", clock.t); !v.Allowed {
				blockedAtCycle = c
				break
			}
		}
		if blockedAtCycle >= 0 {
			t.Logf("  burst %.0fx / pause 1x: blocked at cycle %d (%.0f windows)", mult, blockedAtCycle, float64(blockedAtCycle)*2)
		} else {
			t.Logf("  burst %.0fx / pause 1x: survived all %d cycles (%d windows) unblocked", mult, maxCycles, maxCycles*2)
		}
	}
}

// TestAdversarialBenchmark_SlowNovelToolDrip is
// TestRecallBenchmark_NovelToolEnumeration's drip counterpart: instead
// of a burst of new tools in one window, one brand-new tool per window,
// indefinitely -- novel_tool logs every one of these immediately and
// unconditionally regardless of drip rate (it is not window-gated,
// unlike ml_score's tool_diversity), so recall for *logging* is
// trivially 100% by design; what this measures is whether a slow drip
// ever also crosses ml_score's tool_diversity feature far enough to
// auto-block, the way a single-window burst of 40 does.
func TestAdversarialBenchmark_SlowNovelToolDrip(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	const baseline = 30
	const maxWindows = 150

	rng := rand.New(rand.NewSource(424242))
	identity := "drip-scanner"
	d, blocker, clock, writer := warmDetector(t, rng, cfg, identity, baseline, 20)

	loggedNovel := 0
	blockedAtWindow := -1
	for w := 0; w < maxWindows; w++ {
		before := len(writer.anomalies)
		// One brand-new tool this window, plus ordinary baseline traffic
		// on already-known tools.
		for c := 0; c < baseline-1; c++ {
			d.Publish(auditdomain.Entry{Identity: identity, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
		}
		d.Publish(auditdomain.Entry{Identity: identity, Tool: fmt.Sprintf("drip_tool_%d", w), Decision: "allow"})
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
		d.Publish(auditdomain.Entry{Identity: identity, Tool: "__probe__", Decision: "allow"})

		loggedNovel += len(writer.anomalies) - before
		if v := blocker.Check(identity, "", clock.t); !v.Allowed {
			blockedAtWindow = w
			break
		}
	}
	if blockedAtWindow >= 0 {
		t.Logf("slow novel-tool drip (1 new tool/window): logged %d novel_tool anomalies, auto-blocked at window %d", loggedNovel, blockedAtWindow)
	} else {
		t.Logf("slow novel-tool drip (1 new tool/window): logged %d novel_tool anomalies over %d windows, never auto-blocked", loggedNovel, maxWindows)
	}
}

// TestAdversarialBenchmark_DistributedSybil_WithTenantAnomaly is
// TestAdversarialBenchmark_DistributedSybil's direct counterpart with
// tenant_anomaly also on -- same 20 identities, same 1.5x-baseline
// individual spike, but this time all 20 share ONE Detector and ONE
// tenant (the architectural point of tenant_anomaly: it needs shared
// state across identities, which the original sybil test's 20
// independent Detector instances deliberately did not have). Confirms
// or refutes the closing claim in real code: does the aggregate signal
// actually fire when no individual identity's own heuristics do?
func TestAdversarialBenchmark_DistributedSybil_WithTenantAnomaly(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	cfg.TenantAnomaly = domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 5.0, MinCalls: 10}
	const baseline = 30
	const identities = 20
	const spikeMultiple = 1.5
	const tenant = "shared-tenant"

	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, writer, nil, blocker, nil, clock.now, nil)
	rng := rand.New(rand.NewSource(777))

	identityNames := make([]string, identities)
	for i := range identityNames {
		identityNames[i] = fmt.Sprintf("sybil-shared-%d", i)
	}

	// Warm the TENANT's own aggregate baseline: 20 rounds, each round
	// every identity publishes one ordinary window's worth of jittered
	// traffic, then the clock rolls once for the whole round -- tenant
	// state accumulates across all 20 regardless of which identity each
	// entry came from.
	for round := 0; round < 20; round++ {
		for _, identity := range identityNames {
			calls := baseline - 6 + rng.Intn(13)
			for c := 0; c < calls; c++ {
				d.Publish(auditdomain.Entry{Identity: identity, Tenant: tenant, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
			}
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}

	before := len(writer.anomalies)
	blockedCount := 0
	spikeCalls := int(float64(baseline) * spikeMultiple)
	for _, identity := range identityNames {
		for c := 0; c < spikeCalls; c++ {
			d.Publish(auditdomain.Entry{Identity: identity, Tenant: tenant, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
		}
	}
	clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	// Probe both the per-identity and tenant windows into completing.
	for _, identity := range identityNames {
		d.Publish(auditdomain.Entry{Identity: identity, Tenant: tenant, Tool: "__probe__", Decision: "allow"})
	}
	for _, identity := range identityNames {
		if v := blocker.Check(identity, "", clock.t); !v.Allowed {
			blockedCount++
		}
	}

	tenantFlagged := false
	var tenantDetail string
	for _, a := range writer.anomalies[before:] {
		if a.Kind == domain.KindTenantDrift {
			tenantFlagged = true
			tenantDetail = a.Detail
		}
	}
	t.Logf("distributed sybil WITH tenant_anomaly: %d/%d individually blocked (unchanged from the no-tenant-anomaly test, as expected -- tenant_anomaly never blocks); tenant-aggregate anomaly logged: %v",
		blockedCount, identities, tenantFlagged)
	if tenantFlagged {
		t.Logf("  tenant anomaly detail: %s", tenantDetail)
	}
	if !tenantFlagged {
		t.Error("expected tenant_anomaly to log a tenant-aggregate anomaly for a coordinated 1.5x spike across 20 identities -- the gap this feature exists to close")
	}
	if blockedCount != 0 {
		t.Errorf("tenant_anomaly must never auto-block (no single identity to block for a tenant-level signal) -- got %d/%d individually blocked", blockedCount, identities)
	}
}

// TestAdversarialBenchmark_MimicryCeiling_WithHJitter is
// TestAdversarialBenchmark_MimicryCeiling's counterpart with H jitter
// on: the same sustained-rate sweep, but at the specific 1.15x ceiling
// the unjittered test found safe forever, run across many different
// identities (each gets its own deterministic, secret-keyed jitter).
// Measures the real, honest effect: does jitter cause some fraction of
// identities to get caught at a rate that was previously universally
// safe, or does it do nothing measurable?
func TestAdversarialBenchmark_MimicryCeiling_WithHJitter(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	cfg.Drift.HJitterFraction = 0.2
	cfg.Drift.JitterSecret = []byte("adversarial-benchmark-secret-not-for-prod")
	const baseline = 30
	const maxWindows = 300
	const identitiesPerMultiple = 30
	multiples := []float64{1.10, 1.15, 1.20}

	t.Log("mimicry ceiling WITH h_jitter_fraction=0.2: same sustained rates, 30 identities per multiple (jitter is per-identity, not per-run):")
	for _, mult := range multiples {
		caught := 0
		var caughtAtWindows []int
		for i := 0; i < identitiesPerMultiple; i++ {
			rng := rand.New(rand.NewSource(int64(mult*10000) + int64(i)))
			identity := fmt.Sprintf("mimic-jitter-%v-%d", mult, i)
			d, blocker, clock, _ := warmDetector(t, rng, cfg, identity, baseline, 20)

			plateauCalls := int(float64(baseline) * mult)
			blockedAtWindow := -1
			for w := 0; w < maxWindows; w++ {
				scoreWindow(d, clock, cfg, identity, plateauCalls, benchTools[rng.Intn(len(benchTools))], "allow")
				if v := blocker.Check(identity, "", clock.t); !v.Allowed {
					blockedAtWindow = w
					break
				}
			}
			if blockedAtWindow >= 0 {
				caught++
				caughtAtWindows = append(caughtAtWindows, blockedAtWindow)
			}
		}
		t.Logf("  %.2fx baseline, sustained, 30 identities: %d/%d caught within %d windows (windows-to-catch: %v)",
			mult, caught, identitiesPerMultiple, maxWindows, caughtAtWindows)
	}
}

// TestAdversarialBenchmark_TenantAnomaly_FalsePositiveRate checks the
// new AggregateZScore scoring function (added to fix the bug
// TestAdversarialBenchmark_DistributedSybil_WithTenantAnomaly's own
// history documents) doesn't trade detection power for false positives:
// 10 tenants, 20 identities each, steady ordinary jittered traffic, no
// attack, 100 windows.
func TestAdversarialBenchmark_TenantAnomaly_FalsePositiveRate(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	cfg.TenantAnomaly = domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 5.0, MinCalls: 10}
	const baseline = 30
	const identitiesPerTenant = 20
	const tenants = 10
	const windows = 100

	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, writer, nil, blocker, nil, clock.now, nil)
	rng := rand.New(rand.NewSource(2026))

	for w := 0; w < windows; w++ {
		for tIdx := 0; tIdx < tenants; tIdx++ {
			tenant := fmt.Sprintf("fp-tenant-%d", tIdx)
			for iIdx := 0; iIdx < identitiesPerTenant; iIdx++ {
				identity := fmt.Sprintf("fp-agent-%d-%d", tIdx, iIdx)
				calls := baseline - 6 + rng.Intn(13)
				for c := 0; c < calls; c++ {
					d.Publish(auditdomain.Entry{Identity: identity, Tenant: tenant, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
				}
			}
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}

	tenantFPs := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindTenantDrift {
			tenantFPs++
		}
	}
	totalTenantWindows := tenants * windows
	rate := float64(tenantFPs) / float64(totalTenantWindows)
	t.Logf("tenant_anomaly false-positive rate: %d/%d tenant-windows flagged (%.3f%%) across %d tenants x %d identities x %d windows, steady traffic",
		tenantFPs, totalTenantWindows, rate*100, tenants, identitiesPerTenant, windows)
	if rate > 0.02 {
		t.Errorf("tenant_anomaly false-positive rate %.3f%% exceeds the 2%% budget every other heuristic in this package is held to", rate*100)
	}
}

// TestAdversarialBenchmark_GrowingNovelToolRamp is
// TestAdversarialBenchmark_SlowNovelToolDrip's growing-rate counterpart:
// instead of a flat 1-new-tool/window forever (a constant step the
// baseline absorbs within a few windows, same as any unflagged window
// folding), the count of brand-new tools per window itself increases
// -- 1, then 2, then 3, ... -- the same "ever-moving target the
// baseline mean can never fully catch up to" shape
// TestRecallBenchmark_LowAndSlow_WithDriftDetection already confirmed
// CUSUM closes for call_rate. Tests whether tool_diversity's CUSUM
// closes the equivalent gap for enumeration, or whether the flat-drip
// result generalizes.
func TestAdversarialBenchmark_GrowingNovelToolRamp(t *testing.T) {
	cfg := shippedExampleCfgWithDrift()
	const baseline = 30
	const maxWindows = 150

	rng := rand.New(rand.NewSource(848484))
	identity := "ramp-scanner"
	d, blocker, clock, writer := warmDetector(t, rng, cfg, identity, baseline, 20)

	newToolsThisWindow := 0
	blockedAtWindow := -1
	for w := 0; w < maxWindows; w++ {
		newToolsThisWindow++
		for c := 0; c < baseline-newToolsThisWindow; c++ {
			d.Publish(auditdomain.Entry{Identity: identity, Tool: benchTools[rng.Intn(len(benchTools))], Decision: "allow"})
		}
		for nt := 0; nt < newToolsThisWindow; nt++ {
			d.Publish(auditdomain.Entry{Identity: identity, Tool: fmt.Sprintf("ramp_tool_%d_%d", w, nt), Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
		d.Publish(auditdomain.Entry{Identity: identity, Tool: "__probe__", Decision: "allow"})
		if v := blocker.Check(identity, "", clock.t); !v.Allowed {
			blockedAtWindow = w
			break
		}
	}
	if blockedAtWindow >= 0 {
		t.Logf("growing novel-tool ramp (+1 new tool/window each window): blocked at window %d (%d new tools that window), %d anomalies logged total",
			blockedAtWindow, newToolsThisWindow, len(writer.anomalies))
	} else {
		t.Logf("growing novel-tool ramp (+1 new tool/window each window): never blocked in %d windows (reached %d new tools/window), %d anomalies logged total",
			maxWindows, newToolsThisWindow, len(writer.anomalies))
	}
}
