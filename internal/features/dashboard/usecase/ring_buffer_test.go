package usecase_test

import (
	"sync"
	"testing"
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/usecase"
)

func TestRingBuffer_SinceReturnsOnlyNewer(t *testing.T) {
	b := usecase.NewRingBuffer(10)
	now := time.Now()
	b.Publish(auditdomain.Entry{Identity: "a", Timestamp: now}) // ID 1
	b.Publish(auditdomain.Entry{Identity: "b", Timestamp: now}) // ID 2
	b.Publish(auditdomain.Entry{Identity: "c", Timestamp: now}) // ID 3

	got := b.Since(1, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries after ID 1, got %d", len(got))
	}
	if got[0].Identity != "b" || got[1].Identity != "c" {
		t.Errorf("unexpected entries: %+v", got)
	}
}

func TestRingBuffer_SinceZeroReturnsAll(t *testing.T) {
	b := usecase.NewRingBuffer(10)
	now := time.Now()
	b.Publish(auditdomain.Entry{Identity: "a", Timestamp: now})
	b.Publish(auditdomain.Entry{Identity: "b", Timestamp: now})

	got := b.Since(0, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestRingBuffer_SinceRespectsLimit_KeepsMostRecent(t *testing.T) {
	b := usecase.NewRingBuffer(10)
	now := time.Now()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		b.Publish(auditdomain.Entry{Identity: id, Timestamp: now})
	}

	got := b.Since(0, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (limit), got %d", len(got))
	}
	if got[0].Identity != "d" || got[1].Identity != "e" {
		t.Errorf("expected the 2 most recent entries (d, e), got %+v", got)
	}
}

func TestRingBuffer_EvictsOldestPastCapacity(t *testing.T) {
	b := usecase.NewRingBuffer(3)
	now := time.Now()
	for _, id := range []string{"a", "b", "c", "d"} {
		b.Publish(auditdomain.Entry{Identity: id, Timestamp: now})
	}

	got := b.Since(0, 10)
	if len(got) != 3 {
		t.Fatalf("expected buffer capped at 3, got %d", len(got))
	}
	if got[0].Identity != "b" {
		t.Errorf("expected oldest entry 'a' to have been evicted, got first=%q", got[0].Identity)
	}
}

func TestRingBuffer_ConcurrentPublishAndSince(t *testing.T) {
	b := usecase.NewRingBuffer(100)
	now := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Publish(auditdomain.Entry{Identity: "concurrent", Timestamp: now})
		}()
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.Since(0, 10)
		}()
	}
	wg.Wait()

	got := b.Since(0, 1000)
	if len(got) != 50 {
		t.Errorf("expected 50 published entries, got %d", len(got))
	}
}

func TestRingBuffer_ZeroCapacityDoesNotPanic(t *testing.T) {
	b := usecase.NewRingBuffer(0)
	now := time.Now()
	b.Publish(auditdomain.Entry{Identity: "a", Timestamp: now})
	b.Publish(auditdomain.Entry{Identity: "b", Timestamp: now})

	got := b.Since(0, 10)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry in capacity-1 buffer, got %d", len(got))
	}
	if got[0].Identity != "b" {
		t.Errorf("expected most recent entry 'b', got %q", got[0].Identity)
	}
}

func TestRingBuffer_NegativeCapacityDoesNotPanic(t *testing.T) {
	b := usecase.NewRingBuffer(-5)
	now := time.Now()
	b.Publish(auditdomain.Entry{Identity: "a", Timestamp: now})

	got := b.Since(0, 10)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry in capacity-1 buffer, got %d", len(got))
	}
}
