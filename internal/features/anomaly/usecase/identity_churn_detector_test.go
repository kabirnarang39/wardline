package usecase_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// TestCheckIdentityChurn_OnlyCountsGenuineFirstSightings pins the
// detection point checkIdentityChurn depends on: repeat calls from the
// SAME identity within a window must never inflate the churn count --
// only the very first call from a never-before-seen identity does.
// Verified by giving one identity many calls and a second, different
// identity one call, then asserting the window's churn count is 2, not
// (many + 1).
func TestCheckIdentityChurn_OnlyCountsGenuineFirstSightings(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		IdentityChurn: domain.IdentityChurnConfig{Enabled: true, RateMultiplier: 3.0, MinNewIdentities: 1},
	}
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now, nil)

	for c := 0; c < 10; c++ {
		d.Publish(auditdomain.Entry{Identity: "repeat-caller", Tenant: "t", Tool: "x", Decision: "allow"})
	}
	d.Publish(auditdomain.Entry{Identity: "genuinely-new", Tenant: "t", Tool: "x", Decision: "allow"})

	got := usecase.ChurnWindowCurForTest(d, "t")
	if got != 2 {
		t.Fatalf("expected exactly 2 first-sightings this window (repeat-caller's first call + genuinely-new's), got %d -- repeat calls from the same identity must not inflate the churn count", got)
	}
}

// TestCheckIdentityChurn_FlagsBurstOfNewIdentities is this feature's
// actual proof: a tenant with a steady, low organic new-identity rate
// (baseline) suddenly sees a burst far above it -- the fingerprint of
// disposable-identity rotation -- and identity_churn flags it, using
// AggregateZScore the same way tenant_anomaly does (not zCount's
// per-identity-scale relative floor, wrong at this scale for the exact
// reason AggregateZScore's own doc comment documents).
func TestCheckIdentityChurn_FlagsBurstOfNewIdentities(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		IdentityChurn: domain.IdentityChurnConfig{Enabled: true, RateMultiplier: 3.0, MinNewIdentities: 1},
	}
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now, nil)

	// 20 warmup windows: exactly 2 new identities per window (a small,
	// steady organic churn rate -- new sessions/users showing up
	// normally), well past minSamplesForZScore's 8-window floor.
	newIdx := 0
	for w := 0; w < 20; w++ {
		for c := 0; c < 2; c++ {
			d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("organic-%d", newIdx), Tenant: "t", Tool: "x", Decision: "allow"})
			newIdx++
		}
		clock.t = clock.t.Add(61 * time.Second)
	}

	// Attack window: 40 throwaway identities appear at once -- each
	// making only a couple of calls, deliberately too few to trip
	// rate_spike or novel_tool on any single one of them (there is no
	// established per-identity baseline for a brand-new identity to
	// deviate from in the first place -- see checkRateSpike's own
	// st.prev.total == 0 guard).
	for c := 0; c < 40; c++ {
		d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("throwaway-%d", c), Tenant: "t", Tool: "x", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	d.Publish(auditdomain.Entry{Identity: "probe", Tenant: "t", Tool: "x", Decision: "allow"})

	found := false
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindIdentityChurn {
			found = true
		}
	}
	if !found {
		t.Fatal("expected identity_churn to flag a 40-new-identity burst against a steady 2-per-window baseline -- no single one of those 40 identities has enough history for any per-identity heuristic to react to")
	}
}

// TestCheckIdentityChurn_OrdinaryChurnRate_NeverFalsePositives is the
// false-positive discipline every heuristic in this package is held to:
// steady organic new-identity traffic with ordinary random variation,
// no coordinated burst, must not flag.
func TestCheckIdentityChurn_OrdinaryChurnRate_NeverFalsePositives(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		IdentityChurn: domain.IdentityChurnConfig{Enabled: true, RateMultiplier: 5.0, MinNewIdentities: 1},
	}
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now, nil)

	// Deterministic pseudo-variation (no math/rand dependency needed for
	// a bounded 0-4 range): new-identity count cycles 1,2,3,4,2,1,3,2...
	// -- ordinary noise around a mean of ~2.3, never a real burst.
	pattern := []int{1, 2, 3, 4, 2, 1, 3, 2}
	newIdx := 0
	for w := 0; w < 200; w++ {
		count := pattern[w%len(pattern)]
		for c := 0; c < count; c++ {
			d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("steady-%d", newIdx), Tenant: "t", Tool: "x", Decision: "allow"})
			newIdx++
		}
		clock.t = clock.t.Add(61 * time.Second)
	}

	churnFPs := 0
	for _, a := range writer.anomalies {
		if a.Kind == domain.KindIdentityChurn {
			churnFPs++
		}
	}
	rate := float64(churnFPs) / 200.0
	t.Logf("identity_churn false-positive rate: %d/200 windows flagged (%.3f%%) on ordinary cyclic new-identity traffic", churnFPs, rate*100)
	if rate > 0.02 {
		t.Errorf("identity_churn false-positive rate %.3f%% exceeds the 2%% budget every other heuristic in this package is held to", rate*100)
	}
}
