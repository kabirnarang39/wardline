package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

func TestAlertBuffer_SinceFromStartReturnsEverything(t *testing.T) {
	b := usecase.NewAlertBuffer(10)
	b.Add(domain.Anomaly{Identity: "alice", Kind: domain.KindNovelTool})
	b.Add(domain.Anomaly{Identity: "bob", Kind: domain.KindRateSpike})

	got := b.Since(0, 0)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestAlertBuffer_SinceReturnsOnlyNewerEntries(t *testing.T) {
	b := usecase.NewAlertBuffer(10)
	b.Add(domain.Anomaly{Identity: "alice", Kind: domain.KindNovelTool})
	b.Add(domain.Anomaly{Identity: "bob", Kind: domain.KindRateSpike})

	first := b.Since(0, 0)[0]
	got := b.Since(first.ID, 0)
	if len(got) != 1 || got[0].Identity != "bob" {
		t.Fatalf("expected only bob's entry after the first ID, got %+v", got)
	}
}

func TestAlertBuffer_EvictsOldestPastCapacity(t *testing.T) {
	b := usecase.NewAlertBuffer(2)
	b.Add(domain.Anomaly{Identity: "one"})
	b.Add(domain.Anomaly{Identity: "two"})
	b.Add(domain.Anomaly{Identity: "three"})

	got := b.Since(0, 0)
	if len(got) != 2 {
		t.Fatalf("expected capacity to bound the buffer at 2, got %d", len(got))
	}
	if got[0].Identity != "two" || got[1].Identity != "three" {
		t.Fatalf("expected the oldest entry evicted, got %+v", got)
	}
}

func TestAlertBuffer_LimitCapsResultToMostRecent(t *testing.T) {
	b := usecase.NewAlertBuffer(10)
	b.Add(domain.Anomaly{Identity: "one"})
	b.Add(domain.Anomaly{Identity: "two"})
	b.Add(domain.Anomaly{Identity: "three"})

	got := b.Since(0, 2)
	if len(got) != 2 || got[0].Identity != "two" || got[1].Identity != "three" {
		t.Fatalf("expected the 2 most recent entries, got %+v", got)
	}
}

func TestAlertBuffer_AfterIDAheadOfNextIDTreatedAsFromStart(t *testing.T) {
	b := usecase.NewAlertBuffer(10)
	b.Add(domain.Anomaly{Identity: "one"})

	got := b.Since(999, 0)
	if len(got) != 1 {
		t.Fatalf("expected an afterID ahead of nextID to reset to \"from start\", got %d entries", len(got))
	}
}
