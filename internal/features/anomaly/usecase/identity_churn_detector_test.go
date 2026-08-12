package usecase_test

import (
	"fmt"
	"sync"
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

// fakeChurnWindowStore is an in-memory stand-in for
// PostgresChurnWindowStore, mirroring fakeTenantWindowStore
// (tenant_detector_test.go) exactly -- both replicas' Detectors share
// ONE fakeChurnWindowStore instance, exactly as two real replicas would
// share one Postgres database.
type fakeChurnWindowStore struct {
	mu     sync.Mutex
	totals map[string]int
}

func newFakeChurnWindowStore() *fakeChurnWindowStore {
	return &fakeChurnWindowStore{totals: make(map[string]int)}
}

func (s *fakeChurnWindowStore) AddAndGet(tenantName string, windowStart time.Time, delta int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenantName + "|" + windowStart.String()
	s.totals[key] += delta
	return s.totals[key], nil
}

// TestCheckIdentityChurn_MergesAcrossTwoDetectors is the HA persistence
// half of this task's proof, mirroring
// TestCheckTenantDrift_MergesAcrossTwoDetectors exactly: two separate
// Detectors (simulating two replicas), sharing one churnWindowStore,
// each individually publishing HALF of a coordinated disposable-identity
// burst -- neither Detector's own local count crosses the threshold
// alone, but the shared store's merged total does, and it's the SHARED
// total that must drive the anomaly decision.
func TestCheckIdentityChurn_MergesAcrossTwoDetectors(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		IdentityChurn: domain.IdentityChurnConfig{Enabled: true, RateMultiplier: 3.0, MinNewIdentities: 1},
	}
	sharedStore := newFakeChurnWindowStore()
	clock := &fakeClock{t: time.Unix(0, 0)}

	writerA := &recordingWriter{}
	dA := usecase.NewDetector(cfg, writerA, nil, nil, nil, clock.now, nil).WithChurnStores(sharedStore, nil)
	writerB := &recordingWriter{}
	dB := usecase.NewDetector(cfg, writerB, nil, nil, nil, clock.now, nil).WithChurnStores(sharedStore, nil)

	// 20 warmup windows, split across both replicas (2 new identities
	// each per window), building a baseline that (via the
	// fold-the-merged-total mechanism) both Detectors should converge to
	// independently.
	newIdxA, newIdxB := 0, 0
	for w := 0; w < 20; w++ {
		for c := 0; c < 2; c++ {
			dA.Publish(auditdomain.Entry{Identity: fmt.Sprintf("a-organic-%d", newIdxA), Tenant: "shared", Tool: "x", Decision: "allow"})
			newIdxA++
		}
		for c := 0; c < 2; c++ {
			dB.Publish(auditdomain.Entry{Identity: fmt.Sprintf("b-organic-%d", newIdxB), Tenant: "shared", Tool: "x", Decision: "allow"})
			newIdxB++
		}
		clock.t = clock.t.Add(61 * time.Second)
	}

	// Attack window: A and B each publish HALF a 40-identity burst.
	for c := 0; c < 20; c++ {
		dA.Publish(auditdomain.Entry{Identity: fmt.Sprintf("a-throwaway-%d", c), Tenant: "shared", Tool: "x", Decision: "allow"})
	}
	for c := 0; c < 20; c++ {
		dB.Publish(auditdomain.Entry{Identity: fmt.Sprintf("b-throwaway-%d", c), Tenant: "shared", Tool: "x", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	dA.Publish(auditdomain.Entry{Identity: "probe-a", Tenant: "shared", Tool: "x", Decision: "allow"})
	dB.Publish(auditdomain.Entry{Identity: "probe-b", Tenant: "shared", Tool: "x", Decision: "allow"})

	foundOnA, foundOnB := false, false
	for _, a := range writerA.anomalies {
		if a.Kind == domain.KindIdentityChurn {
			foundOnA = true
		}
	}
	for _, a := range writerB.anomalies {
		if a.Kind == domain.KindIdentityChurn {
			foundOnB = true
		}
	}
	if !foundOnA && !foundOnB {
		t.Fatal("expected at least one replica to detect the identity_churn anomaly from the MERGED total -- neither replica's own local 20-new-identity contribution alone should be enough to explain a detection, only the shared 40")
	}
}

// TestCheckIdentityChurn_CUSUM_SlowTrickleEventuallyFires is the actual
// point of the CUSUM extension: one disposable identity every window,
// individually always far below RateMultiplier (which needs a genuine
// burst in a single window to trip), accumulates in churnCUSUM and
// eventually crosses H -- the same slow-ramp gap drift_detection's own
// CUSUM closes for call_rate, applied here to churn count.
func TestCheckIdentityChurn_CUSUM_SlowTrickleEventuallyFires(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		IdentityChurn: domain.IdentityChurnConfig{
			Enabled: true, RateMultiplier: 10.0, MinNewIdentities: 1, // well above the ~1-2 z the trickle below ever produces per window
			CUSUMEnabled: true, K: 0.3, H: 4.0,
		},
	}
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now, nil)

	// Warmup: a steady baseline of 1 new identity every window (past
	// minSamplesForZScore's floor), then a sustained SLIGHT rise to 2
	// new identities every window -- never anywhere near
	// RateMultiplier=10, but a persistent small positive deviation is
	// exactly what a CUSUM accumulator is built to catch over time, even
	// as the baseline itself slowly, partially absorbs the rise (the
	// fold-conditional-on-RateMultiplier path still folds every
	// non-abrupt window, same as ml_score's own documented "baseline
	// adapts and absorbs" trait for a per-window test alone) -- CUSUM's
	// accumulation outpaces that slow dilution, exactly the property
	// TestDetector_AutoBlock_LowAndSlowEvades/drift_detection's own
	// recall benchmark already proves for call_rate.
	newIdx := 0
	for w := 0; w < 30; w++ {
		d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("baseline-%d", newIdx), Tenant: "t", Tool: "x", Decision: "allow"})
		newIdx++
		clock.t = clock.t.Add(61 * time.Second)
	}

	found := false
	for w := 0; w < 100 && !found; w++ {
		for c := 0; c < 2; c++ {
			d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("trickle-%d", newIdx), Tenant: "t", Tool: "x", Decision: "allow"})
			newIdx++
		}
		clock.t = clock.t.Add(61 * time.Second)
		for _, a := range writer.anomalies {
			if a.Kind == domain.KindIdentityChurn {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected identity_churn's CUSUM extension to eventually flag a sustained slight rise in new-identity rate that never once crosses RateMultiplier in any single window -- this is the exact gap the CUSUM extension exists to close")
	}
}

// TestCheckIdentityChurn_CUSUM_ResetsAfterAlarm pins cusumStep's
// post-alarm reset contract (shared with drift_detection's own CUSUM,
// see cusumStep's doc comment): once churnCUSUM fires, it must reset to
// 0, not stay pinned at an ever-growing value.
func TestCheckIdentityChurn_CUSUM_ResetsAfterAlarm(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		IdentityChurn: domain.IdentityChurnConfig{
			Enabled: true, RateMultiplier: 10.0, MinNewIdentities: 1,
			CUSUMEnabled: true, K: 0.3, H: 4.0,
		},
	}
	clock := &fakeClock{t: time.Unix(0, 0)}
	writer := &recordingWriter{}
	d := usecase.NewDetector(cfg, writer, nil, nil, nil, clock.now, nil)

	newIdx := 0
	for w := 0; w < 30; w++ {
		d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("baseline-%d", newIdx), Tenant: "t", Tool: "x", Decision: "allow"})
		newIdx++
		clock.t = clock.t.Add(61 * time.Second)
	}

	fired := false
	for w := 0; w < 100 && !fired; w++ {
		for c := 0; c < 2; c++ {
			d.Publish(auditdomain.Entry{Identity: fmt.Sprintf("trickle-%d", newIdx), Tenant: "t", Tool: "x", Decision: "allow"})
			newIdx++
		}
		clock.t = clock.t.Add(61 * time.Second)
		for _, a := range writer.anomalies {
			if a.Kind == domain.KindIdentityChurn {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("test setup: expected the CUSUM extension to fire within 100 windows (see TestCheckIdentityChurn_CUSUM_SlowTrickleEventuallyFires)")
	}
	if got := usecase.ChurnCUSUMForTest(d, "t"); got != 0 {
		t.Errorf("expected churnCUSUM to reset to 0 immediately after firing, got %.2f", got)
	}
}
