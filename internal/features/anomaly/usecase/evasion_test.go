package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// evasionConfig is the shipped-example ml_score + auto_block posture used by
// both evasion tests below, so the abrupt-spike control and the low-and-slow
// attacker are judged by the exact same detector configuration.
func evasionConfig() domain.HeuristicConfig {
	return domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore: domain.MLScoreConfig{
			Enabled:        true,
			ScoreThreshold: 4.0,
			MinCalls:       10,
		},
		AutoBlock: domain.AutoBlockConfig{
			Enabled:              true,
			ScoreThreshold:       4.0,
			BlockDurationSeconds: 300,
		},
	}
}

// TestDetector_AutoBlock_AbruptSpikeIsBlocked is the positive control for the
// evasion test below: an identity that behaves normally and then spikes its
// call rate ~10x in a single window trips the ml_score z-score and is
// auto-blocked. This is the attack the README's auto-block claim targets.
func TestDetector_AutoBlock_AbruptSpikeIsBlocked(t *testing.T) {
	cfg := evasionConfig()
	clock := &fakeClock{t: time.Unix(0, 0)}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, &recordingWriter{}, nil, blocker, nil, clock.now, nil)

	// Establish a steady ~30 calls/window baseline.
	for w := 0; w < 20; w++ {
		for c := 0; c < 30; c++ {
			d.Publish(auditdomain.Entry{Identity: "attacker", Tool: "read_file", Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}
	// Abrupt spike: ~10x the baseline in one window.
	for c := 0; c < 300; c++ {
		d.Publish(auditdomain.Entry{Identity: "attacker", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	// One more call in the next window forces the spike window to complete
	// and be evaluated.
	d.Publish(auditdomain.Entry{Identity: "attacker", Tool: "read_file", Decision: "allow"})

	if v := blocker.Check("attacker", "", clock.t); v.Allowed {
		t.Fatal("expected an abrupt ~10x rate spike to be auto-blocked, but the identity was still allowed")
	}
}

// TestDetector_AutoBlock_LowAndSlowEvades documents a KNOWN LIMITATION of the
// self-baselining ml_score detector: an attacker who ramps activity slowly
// enough that each window stays within a few standard deviations of the
// moving baseline is never auto-blocked, because the Welford baseline adapts
// upward to absorb the ramp. By the end the identity is sustaining many times
// its original rate with no block.
//
// This is not a bug to fix by tightening a threshold (that would raise the
// false-positive rate guarded by TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic);
// it is an inherent tradeoff of unsupervised, per-identity baselining. The
// test is a regression guard so the limitation stays documented and honest
// (see docs anomaly-detection "known limitations"). If a future change to the
// detector DOES start blocking this pattern, this test failing is the signal
// to re-examine the false-positive impact and update the docs — not to just
// delete the assertion.
func TestDetector_AutoBlock_LowAndSlowEvades(t *testing.T) {
	cfg := evasionConfig()
	clock := &fakeClock{t: time.Unix(0, 0)}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, &recordingWriter{}, nil, blocker, nil, clock.now, nil)

	// Baseline: ~30 calls/window.
	calls := 30
	for w := 0; w < 20; w++ {
		for c := 0; c < calls; c++ {
			d.Publish(auditdomain.Entry{Identity: "creeper", Tool: "read_file", Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}

	// Slow ramp: +3 calls/window for 40 windows. Final rate is ~150/window
	// (5x baseline), reached gradually so no single window is anomalous
	// relative to the baseline the previous windows established.
	for w := 0; w < 40; w++ {
		calls += 3
		for c := 0; c < calls; c++ {
			d.Publish(auditdomain.Entry{Identity: "creeper", Tool: "read_file", Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)

		if v := blocker.Check("creeper", "", clock.t); !v.Allowed {
			t.Fatalf("low-and-slow attacker was auto-blocked at window %d (rate %d/window): if this is intended, "+
				"re-check the false-positive impact and update the anomaly-detection docs before changing this test", w, calls)
		}
	}
}

// TestDetector_AutoBlock_DriftDetectionCatchesLowAndSlow is
// TestDetector_AutoBlock_LowAndSlowEvades' direct counterpart with
// drift_detection (CUSUM) turned on: the exact same identity, baseline,
// and ramp that evades ml_score/auto_block alone is caught well before
// this test's own ramp even finishes -- see domain.DriftConfig's doc
// comment for why a per-window z-score test and a cumulative-sum test
// close different gaps rather than one superseding the other.
func TestDetector_AutoBlock_DriftDetectionCatchesLowAndSlow(t *testing.T) {
	cfg := evasionConfig()
	cfg.Drift = domain.DriftConfig{Enabled: true, K: 0.5, H: 5.0, MinCalls: 5}
	clock := &fakeClock{t: time.Unix(0, 0)}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, &recordingWriter{}, nil, blocker, nil, clock.now, nil)

	// Identical baseline and ramp to TestDetector_AutoBlock_LowAndSlowEvades.
	calls := 30
	for w := 0; w < 20; w++ {
		for c := 0; c < calls; c++ {
			d.Publish(auditdomain.Entry{Identity: "creeper", Tool: "read_file", Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}

	blocked := false
	for w := 0; w < 40; w++ {
		calls += 3
		for c := 0; c < calls; c++ {
			d.Publish(auditdomain.Entry{Identity: "creeper", Tool: "read_file", Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)

		if v := blocker.Check("creeper", "", clock.t); !v.Allowed {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Fatal("expected drift_detection to auto-block the same low-and-slow ramp that evades ml_score/auto_block alone, within 40 windows")
	}
}
