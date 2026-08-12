package usecase_test

import (
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/usecase"
)

func TestCorrelatedAlertBuffer_AddAndSinceZero_ReturnsAll(t *testing.T) {
	b := usecase.NewCorrelatedAlertBuffer(10)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	b.Add(domain.CorrelatedAlert{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})
	b.Add(domain.CorrelatedAlert{Fingerprint: "fp2", Kind: anomalydomain.KindNovelTool, InstanceIDs: []string{"a", "c"}, FirstSeen: now, LastSeen: now})

	entries := b.Since(0, 0, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID != 1 || entries[1].ID != 2 {
		t.Errorf("expected monotonic IDs 1, 2 -- got %d, %d", entries[0].ID, entries[1].ID)
	}
}

func TestCorrelatedAlertBuffer_BoundedCapacity_EvictsOldest(t *testing.T) {
	b := usecase.NewCorrelatedAlertBuffer(2)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	b.Add(domain.CorrelatedAlert{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})
	b.Add(domain.CorrelatedAlert{Fingerprint: "fp2", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})
	b.Add(domain.CorrelatedAlert{Fingerprint: "fp3", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})

	entries := b.Since(0, 0, "")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (capacity 2), got %d", len(entries))
	}
	if entries[0].Fingerprint != "fp2" || entries[1].Fingerprint != "fp3" {
		t.Errorf("expected oldest (fp1) evicted, got %q then %q", entries[0].Fingerprint, entries[1].Fingerprint)
	}
}

func TestCorrelatedAlertBuffer_SinceAfterID_ReturnsOnlyNewer(t *testing.T) {
	b := usecase.NewCorrelatedAlertBuffer(10)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	b.Add(domain.CorrelatedAlert{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})
	b.Add(domain.CorrelatedAlert{Fingerprint: "fp2", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})

	entries := b.Since(1, 0, "")
	if len(entries) != 1 || entries[0].Fingerprint != "fp2" {
		t.Fatalf("expected only fp2 after ID 1, got %+v", entries)
	}
}

func TestCorrelatedAlertBuffer_SinceAfterIDAheadOfNext_TreatedAsFromStart(t *testing.T) {
	b := usecase.NewCorrelatedAlertBuffer(10)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	b.Add(domain.CorrelatedAlert{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})

	entries := b.Since(999, 0, "")
	if len(entries) != 1 {
		t.Fatalf("expected restart-handling fallback to return from-start, got %d entries", len(entries))
	}
}

// TestCorrelatedAlertBuffer_SinceFiltersByTenant mirrors
// RingBuffer.Since's own tenant-filter contract: the correlated-alerts
// view can now be scoped per-tenant like every other dashboard view.
func TestCorrelatedAlertBuffer_SinceFiltersByTenant(t *testing.T) {
	b := usecase.NewCorrelatedAlertBuffer(10)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	b.Add(domain.CorrelatedAlert{Fingerprint: "fp1", Tenant: "acme", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})
	b.Add(domain.CorrelatedAlert{Fingerprint: "fp2", Tenant: "widgets-inc", Kind: anomalydomain.KindRateSpike, InstanceIDs: []string{"a", "b"}, FirstSeen: now, LastSeen: now})

	entries := b.Since(0, 0, "acme")
	if len(entries) != 1 || entries[0].Fingerprint != "fp1" {
		t.Fatalf("expected only acme's fp1, got %+v", entries)
	}
}
