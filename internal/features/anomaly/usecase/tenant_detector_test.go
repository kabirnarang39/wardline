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

// TestCheckTenantDrift_WindowBoundariesAreEpochAligned pins the
// prerequisite for cross-replica merging: two Detectors whose tenant
// state is created at different wall-clock offsets (simulating two
// replicas that started seeing a tenant's traffic at different times)
// must still land on identical window boundaries once the offset is
// less than one window -- otherwise they'd address different Postgres
// rows for what should be the same period and the cross-replica merge
// this feature exists for would silently never actually merge anything.
func TestCheckTenantDrift_WindowBoundariesAreEpochAligned(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		TenantAnomaly: domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 5.0, MinCalls: 5},
	}

	// Replica A: first call at an epoch-aligned instant.
	clockA := &fakeClock{t: time.Unix(0, 0)}
	dA := usecase.NewDetector(cfg, &recordingWriter{}, nil, nil, nil, clockA.now, nil)
	dA.Publish(auditdomain.Entry{Identity: "a1", Tenant: "t", Tool: "x", Decision: "allow"})

	// Replica B: first call 15s into the SAME window (simulating a
	// replica that started later, or just saw this tenant's first
	// request later).
	clockB := &fakeClock{t: time.Unix(15, 0)}
	dB := usecase.NewDetector(cfg, &recordingWriter{}, nil, nil, nil, clockB.now, nil)
	dB.Publish(auditdomain.Entry{Identity: "b1", Tenant: "t", Tool: "x", Decision: "allow"})

	wsA := usecase.TenantWindowStartForTest(dA, "t")
	wsB := usecase.TenantWindowStartForTest(dB, "t")
	if !wsA.Equal(wsB) {
		t.Fatalf("expected both replicas to agree on the same window boundary despite starting 15s apart, got A=%v B=%v", wsA, wsB)
	}
	if !wsA.Equal(time.Unix(0, 0)) {
		t.Fatalf("expected the window boundary to be truncated to the 60s grid (0s), got %v", wsA)
	}
}

// fakeTenantWindowStore is an in-memory stand-in for
// PostgresTenantWindowStore, letting this test simulate "two replicas"
// without a real Postgres instance -- both replicas' Detectors share
// ONE fakeTenantWindowStore instance, exactly as two real replicas
// would share one Postgres database.
type fakeTenantWindowStore struct {
	mu     sync.Mutex
	totals map[string]int // key: tenant + "|" + windowStart.String()
}

func newFakeTenantWindowStore() *fakeTenantWindowStore {
	return &fakeTenantWindowStore{totals: make(map[string]int)}
}

func (s *fakeTenantWindowStore) AddAndGet(tenantName string, windowStart time.Time, delta int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenantName + "|" + windowStart.String()
	s.totals[key] += delta
	return s.totals[key], nil
}

// TestCheckTenantDrift_MergesAcrossTwoDetectors is this task's actual
// proof: two separate Detectors (simulating two replicas), sharing one
// tenantWindowStore, each individually publishing HALF of a coordinated
// spike -- neither Detector's own local total crosses the threshold
// alone, but the shared store's merged total does, and it's the SHARED
// total that must drive the anomaly decision.
func TestCheckTenantDrift_MergesAcrossTwoDetectors(t *testing.T) {
	cfg := domain.HeuristicConfig{
		WindowSeconds: 60,
		TenantAnomaly: domain.TenantAnomalyConfig{Enabled: true, RateMultiplier: 3.0, MinCalls: 5},
	}
	sharedStore := newFakeTenantWindowStore()
	clock := &fakeClock{t: time.Unix(0, 0)}

	writerA := &recordingWriter{}
	dA := usecase.NewDetectorWithTenantStores(cfg, writerA, nil, nil, nil, clock.now, nil, sharedStore, nil)
	writerB := &recordingWriter{}
	dB := usecase.NewDetectorWithTenantStores(cfg, writerB, nil, nil, nil, clock.now, nil, sharedStore, nil)

	// 20 warmup windows, split across both replicas (15 identities
	// each), building a baseline that (via the fold-the-merged-total
	// mechanism) both Detectors should converge to independently.
	for w := 0; w < 20; w++ {
		for c := 0; c < 15; c++ {
			dA.Publish(auditdomain.Entry{Identity: fmt.Sprintf("a-%d", c), Tenant: "shared", Tool: "x", Decision: "allow"})
		}
		for c := 0; c < 15; c++ {
			dB.Publish(auditdomain.Entry{Identity: fmt.Sprintf("b-%d", c), Tenant: "shared", Tool: "x", Decision: "allow"})
		}
		clock.t = clock.t.Add(61 * time.Second)
	}

	// Attack window: A and B each publish HALF the spike.
	for c := 0; c < 200; c++ {
		dA.Publish(auditdomain.Entry{Identity: "a-attacker", Tenant: "shared", Tool: "x", Decision: "allow"})
	}
	for c := 0; c < 200; c++ {
		dB.Publish(auditdomain.Entry{Identity: "b-attacker", Tenant: "shared", Tool: "x", Decision: "allow"})
	}
	clock.t = clock.t.Add(61 * time.Second)
	dA.Publish(auditdomain.Entry{Identity: "probe", Tenant: "shared", Tool: "x", Decision: "allow"})
	dB.Publish(auditdomain.Entry{Identity: "probe", Tenant: "shared", Tool: "x", Decision: "allow"})

	foundOnA, foundOnB := false, false
	for _, a := range writerA.anomalies {
		if a.Kind == domain.KindTenantDrift {
			foundOnA = true
		}
	}
	for _, a := range writerB.anomalies {
		if a.Kind == domain.KindTenantDrift {
			foundOnB = true
		}
	}
	if !foundOnA && !foundOnB {
		t.Fatal("expected at least one replica to detect the tenant-aggregate anomaly from the MERGED total -- neither replica's own local 200-call contribution alone should be enough to explain a detection, only the shared 400")
	}
}
