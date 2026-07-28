package usecase_test

import (
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
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, clock.now)

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
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, clock.now)

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
	d := usecase.NewDetector(cfg, writer, nil, nil, clock.now)

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
	d := usecase.NewDetector(cfg, writer, nil, nil, clock.now)

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
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, clock.now)

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

func TestDetector_RateSpike_IsolatedPerIdentity(t *testing.T) {
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(baseCfg(), writer, nil, nil, clock.now)

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
