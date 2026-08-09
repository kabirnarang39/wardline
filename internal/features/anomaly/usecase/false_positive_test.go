package usecase_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic quantifies the
// flagship ml_score detector's false-positive rate on ordinary,
// steady-state traffic — the claim in the README that auto_block won't
// fire on normal agents. It feeds a single identity ~30 calls/window with
// ordinary ±20% jitter across many windows and asserts the detector stays
// well under a 2% false-positive budget. This is a regression guard for
// the warmup floor (minSamplesForZScore) and relative-stddev floor
// (minStddevRelFraction) that prior backprop'd false positives motivated.
func TestDetector_MLScore_FalsePositiveRateOnSteadyTraffic(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		MLScore: domain.MLScoreConfig{
			Enabled:        true,
			ScoreThreshold: 4.0, // matches the shipped example config
			MinCalls:       10,
		},
	}
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now, nil)

	rng := rand.New(rand.NewSource(1))
	tools := []string{"read_file", "list_dir", "stat", "search"}

	const windows = 300
	for w := 0; w < windows; w++ {
		calls := 24 + rng.Intn(13) // 24..36, mean ~30, ordinary variation
		for c := 0; c < calls; c++ {
			d.Publish(auditdomain.Entry{
				Identity: "steady",
				Tool:     tools[rng.Intn(len(tools))],
				Decision: "allow",
			})
		}
		clock.t = clock.t.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	}

	fp := len(writer.anomalies)
	rate := float64(fp) / float64(windows)
	t.Logf("ml_score false positives on steady traffic: %d/%d (%.2f%%)", fp, windows, rate*100)
	if rate > 0.02 {
		t.Errorf("false-positive rate %.2f%% exceeds 2%% budget on steady traffic (%d/%d windows flagged)",
			rate*100, fp, windows)
	}
}
