package usecase

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

type noopWriter struct{}

func (noopWriter) Write(domain.Anomaly) error { return nil }

func TestDetector_GC_DropsStaleStateKeepsFreshState(t *testing.T) {
	base := time.Unix(0, 0)
	cur := base
	cfg := domain.HeuristicConfig{WindowSeconds: 60}
	d := NewDetector(cfg, noopWriter{}, nil, nil, nil, func() time.Time { return cur }, nil)
	d.Publish(auditdomain.Entry{Identity: "stale-identity", Tool: "read_file", Decision: "allow"})
	cur = base.Add(5 * time.Minute)
	d.Publish(auditdomain.Entry{Identity: "fresh-identity", Tool: "read_file", Decision: "allow"})

	// GC with a 2-minute interval means anything not seen in the last 4
	// minutes (2x interval) is dropped -- stale-identity (last seen at
	// t=0, now t=5m) qualifies; fresh-identity (last seen at t=5m) does not.
	d.gc(cur, 2*time.Minute)

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.state[tenantIdentityKey("", "stale-identity")]; ok {
		t.Error("expected stale-identity's state to be evicted")
	}
	if _, ok := d.state[tenantIdentityKey("", "fresh-identity")]; !ok {
		t.Error("expected fresh-identity's state to survive the GC pass")
	}
}

func TestGC_SavesToStoreWhenConfigured(t *testing.T) {
	store := &fakeBaselineStore{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60}
	d := NewDetector(cfg, noopWriter{}, nil, nil, nil, time.Now, store)
	d.Publish(auditdomain.Entry{Identity: "alice", Tenant: "acme", Tool: "read_file", Decision: "allow"})

	d.gc(time.Now(), time.Minute)

	if store.saveCalls != 1 {
		t.Fatalf("expected gc to call SaveAll exactly once, got %d", store.saveCalls)
	}
	if _, ok := store.saved["4:acmealice"]; !ok {
		t.Errorf("expected the live identity's snapshot in the saved map, got %v", store.saved)
	}
}

func TestGC_SkipsSaveWhenStoreIsNil(t *testing.T) {
	cfg := domain.HeuristicConfig{WindowSeconds: 60}
	d := NewDetector(cfg, noopWriter{}, nil, nil, nil, time.Now, nil)
	d.Publish(auditdomain.Entry{Identity: "alice", Tenant: "acme", Tool: "read_file", Decision: "allow"})

	d.gc(time.Now(), time.Minute) // must not panic with a nil store
}

func TestGC_SavesRemainingEntriesEvenAfterEvictingExpiredOnes(t *testing.T) {
	store := &fakeBaselineStore{}
	cfg := domain.HeuristicConfig{WindowSeconds: 60}
	d := NewDetector(cfg, noopWriter{}, nil, nil, nil, time.Now, store)
	base := time.Now()
	d.recordAndCheck(auditdomain.Entry{Identity: "stale", Tenant: "acme", Tool: "read_file", Decision: "allow", Timestamp: base})
	d.mu.Lock()
	d.state[tenantIdentityKey("acme", "stale")].lastSeen = base.Add(-time.Hour) // force-expire, bypassing the real clock
	d.mu.Unlock()
	d.recordAndCheck(auditdomain.Entry{Identity: "fresh", Tenant: "acme", Tool: "read_file", Decision: "allow", Timestamp: base})

	d.gc(base, time.Minute) // 2x interval cutoff = base-2min, well after "stale"'s forced lastSeen

	if len(store.saved) != 1 {
		t.Fatalf("expected exactly the surviving identity saved, got %d entries: %v", len(store.saved), store.saved)
	}
}
