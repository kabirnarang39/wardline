package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

func TestBlockChecker_UnblockedIdentity_Allowed(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	v := b.Check("agent-abc123", "acme", now)
	if !v.Allowed {
		t.Fatalf("expected an identity with no block to be allowed, got %+v", v)
	}
}

func TestBlockChecker_BlockedIdentity_DeniedWithRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "acme", "ml_score exceeded threshold")

	v := b.Check("agent-abc123", "acme", now)
	if v.Allowed {
		t.Fatal("expected the blocked identity to be denied")
	}
	if v.RetryAfter != 300*time.Second {
		t.Errorf("expected RetryAfter of 300s (full duration, checked immediately after blocking), got %v", v.RetryAfter)
	}
	if v.Reason == "" {
		t.Error("expected a non-empty reason")
	}
}

func TestBlockChecker_BlockExpires_AllowedAgain(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "acme", "ml_score exceeded threshold")

	later := now.Add(301 * time.Second)
	v := b.Check("agent-abc123", "acme", later)
	if !v.Allowed {
		t.Fatalf("expected the block to have expired, got %+v", v)
	}
}

func TestBlockChecker_DifferentIdentity_Unaffected(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "acme", "ml_score exceeded threshold")

	v := b.Check("agent-xyz789", "acme", now)
	if !v.Allowed {
		t.Fatal("expected a different identity to be unaffected by another identity's block")
	}
}

// TestBlockChecker_SameIdentityDifferentTenant_Unaffected is the
// primitive-level regression gate for Task 22's cross-tenant bleed fix:
// two different tenants can plausibly provision an identically-named
// identity (e.g. two IdPs both provisioning "alice" via SCIM), and a
// block on one tenant's "alice" must never affect the other's.
func TestBlockChecker_SameIdentityDifferentTenant_Unaffected(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("alice", "acme", "ml_score exceeded threshold")

	if v := b.Check("alice", "widgets-inc", now); !v.Allowed {
		t.Fatal("expected a different tenant's identically-named identity to be unaffected by another tenant's block")
	}
	// Sanity: the tenant+identity combo the Block call actually targeted
	// is still blocked.
	if v := b.Check("alice", "acme", now); v.Allowed {
		t.Fatal("expected acme's alice to remain blocked")
	}
}

func TestBlockChecker_List_ReturnsCurrentlyBlockedEntries(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "acme", "ml_score exceeded threshold")

	entries := b.List("")
	if len(entries) != 1 {
		t.Fatalf("expected 1 blocked entry, got %d", len(entries))
	}
	if entries[0].Identity != "agent-abc123" {
		t.Errorf("expected identity agent-abc123, got %q", entries[0].Identity)
	}
	if entries[0].Tenant != "acme" {
		t.Errorf("expected tenant acme, got %q", entries[0].Tenant)
	}
	if entries[0].Reason == "" {
		t.Error("expected a non-empty reason")
	}
	// BlockedSince backs the dashboard Blocked view's "Since" column --
	// must be the real moment Block() was called, not zero-valued.
	if !entries[0].BlockedSince.Equal(now) {
		t.Errorf("expected BlockedSince = %v (the real block time), got %v", now, entries[0].BlockedSince)
	}
	if !entries[0].BlockedUntil.Equal(now.Add(300 * time.Second)) {
		t.Errorf("expected BlockedUntil = %v, got %v", now.Add(300*time.Second), entries[0].BlockedUntil)
	}
}

// TestBlockChecker_List_FiltersExpiredEntriesWithoutGC proves List()
// itself filters by current time -- deliberately without ever calling
// GCBlocksOnce -- so an expired block cannot linger in the dashboard's
// "currently blocked" view for up to a full GC interval after it
// actually expired (GC is memory hygiene for the map, a separate concern
// from what a read of List() should honestly report right now).
func TestBlockChecker_List_FiltersExpiredEntriesWithoutGC(t *testing.T) {
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return current })

	b.Block("agent-abc123", "acme", "ml_score exceeded threshold")

	current = current.Add(301 * time.Second) // past the 300s TTL, GC interval typically much longer (e.g. 600s) and never run here
	entries := b.List("")
	if len(entries) != 0 {
		t.Fatalf("expected List() to filter out the expired entry on its own, got %+v", entries)
	}
}

func TestBlockChecker_Unblock_RemovesActiveBlock(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{BlockDurationSeconds: 900}, func() time.Time { return now })
	b.Block("alice", "acme", "test block")

	if v := b.Check("alice", "acme", now); v.Allowed {
		t.Fatal("setup: expected alice to be blocked before Unblock")
	}

	if removed := b.Unblock("alice", "acme"); !removed {
		t.Error("expected Unblock to report an entry was removed")
	}
	if v := b.Check("alice", "acme", now); !v.Allowed {
		t.Error("expected alice to no longer be blocked after Unblock")
	}
}

// TestBlockChecker_Unblock_ExpiredEntryNotYetGCdReturnsFalse is M2's
// regression test (final review): Unblock must compare against the same
// expired() the other three readers of b.blocked (Check, List,
// GCBlocksOnce) use, not a bare map-presence check. A block whose TTL has
// already elapsed but whose entry GCBlocksOnce hasn't yet swept reads as
// "not blocked" everywhere else (Check already allows it, List already
// omits it) -- Unblock must agree: there's nothing left to "unblock", so
// it must report false, not true.
func TestBlockChecker_Unblock_ExpiredEntryNotYetGCdReturnsFalse(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{BlockDurationSeconds: 300}, func() time.Time { return now })
	b.Block("alice", "acme", "test block")

	now = now.Add(301 * time.Second) // past the TTL; GCBlocksOnce deliberately never called

	if removed := b.Unblock("alice", "acme"); removed {
		t.Error("expected Unblock to report false for an already-expired (but not yet GC'd) entry")
	}
	// Sanity: the stale entry is gone from the map now too (Unblock's own
	// cleanup), not just reported correctly.
	if v := b.Check("alice", "acme", now); !v.Allowed {
		t.Error("expected alice to remain unblocked (already expired) after the no-op Unblock")
	}
}

func TestBlockChecker_Unblock_NeverBlockedReturnsFalse(t *testing.T) {
	now := time.Now()
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{BlockDurationSeconds: 900}, func() time.Time { return now })
	if removed := b.Unblock("nobody", "acme"); removed {
		t.Error("expected Unblock on a never-blocked identity to report false")
	}
}

func TestBlockChecker_Unblock_DoesNotAffectOtherTenant(t *testing.T) {
	now := time.Now()
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{BlockDurationSeconds: 900}, func() time.Time { return now })
	b.Block("alice", "acme", "test block")
	b.Block("alice", "widgets-inc", "different tenant, same identity name")

	b.Unblock("alice", "acme")

	if v := b.Check("alice", "widgets-inc", now); v.Allowed {
		t.Error("unblocking acme's alice must not affect widgets-inc's alice")
	}
}

func TestBlockChecker_List_FiltersByTenant(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("alice", "acme", "ml_score exceeded threshold")
	b.Block("bob", "widgets-inc", "ml_score exceeded threshold")

	got := b.List("acme")
	if len(got) != 1 || got[0].Identity != "alice" {
		t.Fatalf("tenant-filtered List = %+v, want only acme's alice entry", got)
	}

	got = b.List("")
	if len(got) != 2 {
		t.Fatalf("unfiltered List = %+v, want both entries", got)
	}
}
