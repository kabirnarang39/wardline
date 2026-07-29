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

	v := b.Check("agent-abc123", now)
	if !v.Allowed {
		t.Fatalf("expected an identity with no block to be allowed, got %+v", v)
	}
}

func TestBlockChecker_BlockedIdentity_DeniedWithRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "ml_score exceeded threshold")

	v := b.Check("agent-abc123", now)
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

	b.Block("agent-abc123", "ml_score exceeded threshold")

	later := now.Add(301 * time.Second)
	v := b.Check("agent-abc123", later)
	if !v.Allowed {
		t.Fatalf("expected the block to have expired, got %+v", v)
	}
}

func TestBlockChecker_DifferentIdentity_Unaffected(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "ml_score exceeded threshold")

	v := b.Check("agent-xyz789", now)
	if !v.Allowed {
		t.Fatal("expected a different identity to be unaffected by another identity's block")
	}
}

func TestBlockChecker_List_ReturnsCurrentlyBlockedEntries(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 300}, func() time.Time { return now })

	b.Block("agent-abc123", "ml_score exceeded threshold")

	entries := b.List()
	if len(entries) != 1 {
		t.Fatalf("expected 1 blocked entry, got %d", len(entries))
	}
	if entries[0].Identity != "agent-abc123" {
		t.Errorf("expected identity agent-abc123, got %q", entries[0].Identity)
	}
	if entries[0].Reason == "" {
		t.Error("expected a non-empty reason")
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

	b.Block("agent-abc123", "ml_score exceeded threshold")

	current = current.Add(301 * time.Second) // past the 300s TTL, GC interval typically much longer (e.g. 600s) and never run here
	entries := b.List()
	if len(entries) != 0 {
		t.Fatalf("expected List() to filter out the expired entry on its own, got %+v", entries)
	}
}
