package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// TestDetector_AutoBlock_DenyRatioNotVetoedByNoisyToolCallsSign is a
// deterministic regression test for the bug TestRecallBenchmark_DenyRateSpike
// surfaced (see docs/features/anomaly-detection.md's "Recall benchmark"
// section): maxHarmfulZ's deny-ratio volume-decline gate used to be a bare
// `zToolCalls >= 0` check, which is effectively a coin flip whenever
// toolCalls sits within its own baseline's ordinary noise band -- exactly
// the case here, and exactly the case for any real deny-rate attack that
// doesn't itself change call volume.
//
// This test fixes toolCalls' baseline at a constant 32/window (deny_ratio's
// own baseline stays at a constant 0), then attacks with a clean 50%
// deny-ratio spike at 30 calls -- toolCalls dips slightly *below* its own
// baseline (30 < 32) purely because some of this window's calls are
// denies, not allows, giving a small negative zToolCalls (about -0.42,
// well within one standard deviation) alongside an unambiguous deny_ratio
// anomaly. Before the volumeDeclineMargin fix, that negative sign alone
// silently excluded deny_ratio from ever driving an auto-block, no matter
// how severe -- this test pins that the fix (a one-sigma hysteresis
// margin, not a bare zero cutoff) closes it.
func TestDetector_AutoBlock_DenyRatioNotVetoedByNoisyToolCallsSign(t *testing.T) {
	cfg := evasionConfig()
	clock := &fakeClock{t: time.Unix(0, 0)}
	blocker := usecase.NewBlockChecker(cfg.AutoBlock, clock.now)
	d := usecase.NewDetector(cfg, &recordingWriter{}, nil, blocker, nil, clock.now, nil)

	// Baseline: 20 windows of exactly 32 allow calls each. toolCalls'
	// baseline mean lands at 32 with zero sample variance (every window
	// identical) -- deliberately so the attack window's smaller volume
	// (30, purely a byproduct of denies replacing some allows) produces a
	// small but real negative zToolCalls, not zero.
	for w := 0; w < 20; w++ {
		for c := 0; c < 32; c++ {
			d.Publish(auditdomain.Entry{Identity: "denier", Tool: "read_file", Decision: "allow"})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}

	// Attack: 30 calls, 50% denied. deny_ratio baseline is a constant 0
	// (every warmup window was all-allow), so this window's 0.5 ratio is
	// an unambiguous spike; toolCalls (30) is a mild, noise-scale dip
	// below its own baseline (32), not a genuine volume collapse.
	for c := 0; c < 15; c++ {
		d.Publish(auditdomain.Entry{Identity: "denier", Tool: "read_file", Decision: "deny"})
	}
	for c := 0; c < 15; c++ {
		d.Publish(auditdomain.Entry{Identity: "denier", Tool: "read_file", Decision: "allow"})
	}
	clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	// One more call in the next window forces the attack window to
	// complete and be evaluated (see evasion_test.go's identical pattern).
	d.Publish(auditdomain.Entry{Identity: "denier", Tool: "read_file", Decision: "allow"})

	if v := blocker.Check("denier", "", clock.t); v.Allowed {
		t.Fatal("expected a clean 50% deny-ratio spike to auto-block despite toolCalls sitting slightly (noise-scale) below its own baseline")
	}
}
