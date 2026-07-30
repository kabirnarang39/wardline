package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

func TestBlockGC_DropsExpiredEntries(t *testing.T) {
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 60}, func() time.Time { return current })

	b.Block("agent-abc123", "acme", "test")

	current = current.Add(2 * time.Hour) // well past both the block TTL and any reasonable GC interval
	usecase.GCBlocksOnce(b, current)

	if len(b.List("")) != 0 {
		t.Fatal("expected the expired block entry to be dropped after GC")
	}
}

func TestBlockGC_KeepsActiveEntries(t *testing.T) {
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	b := usecase.NewBlockChecker(domain.AutoBlockConfig{Enabled: true, BlockDurationSeconds: 3600}, func() time.Time { return current })

	b.Block("agent-abc123", "acme", "test")

	current = current.Add(1 * time.Minute) // well within the 1h block
	usecase.GCBlocksOnce(b, current)

	if len(b.List("")) != 1 {
		t.Fatal("expected the still-active block entry to survive GC")
	}
}
