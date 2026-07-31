package adapter

import (
	"fmt"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// TestInMemoryLimiter_EvictsExpiredBucketsOnSweep proves the periodic sweep
// in Allow actually removes expired buckets, not just that lookups reset
// them. White-box (package adapter, not adapter_test) so it can inspect
// l.buckets directly instead of adding an exported accessor just for this.
func TestInMemoryLimiter_EvictsExpiredBucketsOnSweep(t *testing.T) {
	l := NewInMemoryLimiter(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Phase 1: create evictionSweepInterval distinct, never-revisited
	// buckets at `now`. The last call in this phase lands exactly on a
	// sweep boundary, but nothing has expired yet (all windows start at
	// `now`), so all buckets should still be present.
	for i := 0; i < evictionSweepInterval; i++ {
		l.Allow(fmt.Sprintf("stale-%d", i), "", "", now)
	}
	if got := len(l.buckets); got != evictionSweepInterval {
		t.Fatalf("expected %d buckets after phase 1, got %d", evictionSweepInterval, got)
	}

	// Phase 2: advance past the window, then drive evictionSweepInterval
	// more calls against a single, different identity so the next sweep
	// boundary is hit again. None of the stale-* identities are looked up
	// again in this phase, so if they disappear it can only be the sweep
	// that removed them (not the per-lookup reset-on-access path already
	// covered by TestInMemoryLimiter_ResetsOnNewWindow).
	later := now.Add(time.Minute + time.Second)
	for i := 0; i < evictionSweepInterval; i++ {
		l.Allow("same-id", "", "", later)
	}

	if got := len(l.buckets); got != 1 {
		t.Fatalf("expected sweep to evict all stale buckets, leaving only same-id's bucket; got %d buckets", got)
	}
	if _, ok := l.buckets[tenant.Key("", "same-id")]; !ok {
		t.Fatal("expected same-id's own bucket to survive")
	}
}
