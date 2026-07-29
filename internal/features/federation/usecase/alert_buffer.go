package usecase

import (
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

// CorrelatedAlertEntry is a domain.CorrelatedAlert plus a monotonic ID
// assigned by CorrelatedAlertBuffer, giving API consumers
// (/dashboard/api/federation/correlated) the same after-ID pagination
// shape as every other ring buffer in this codebase.
type CorrelatedAlertEntry struct {
	ID int64
	domain.CorrelatedAlert
}

// CorrelatedAlertBuffer is a bounded, in-memory, most-recent-N store of
// CorrelatedAlertEntry values -- structurally identical to
// anomaly/usecase.AlertBuffer, kept as its own type per this codebase's
// per-feature vertical-slice convention. Safe for concurrent use.
type CorrelatedAlertBuffer struct {
	mu      sync.Mutex
	cap     int
	entries []CorrelatedAlertEntry
	nextID  int64
}

func NewCorrelatedAlertBuffer(capacity int) *CorrelatedAlertBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &CorrelatedAlertBuffer{cap: capacity, entries: make([]CorrelatedAlertEntry, 0, capacity)}
}

// Add implements the alertSink interface Correlator's onAlert callback
// is wired to in main.go (Task 9).
func (b *CorrelatedAlertBuffer) Add(a domain.CorrelatedAlert) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	entry := CorrelatedAlertEntry{ID: b.nextID, CorrelatedAlert: a}

	if len(b.entries) >= b.cap {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

// Since returns entries with ID > afterID, oldest first, capped to the
// most recent limit of them (afterID=0 means "from the start"; limit <=
// 0 means no cap). Identical restart-handling semantics to every other
// ring buffer in this codebase: an afterID ahead of nextID is treated as
// "from the start".
func (b *CorrelatedAlertBuffer) Since(afterID int64, limit int) []CorrelatedAlertEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	if afterID > b.nextID {
		afterID = 0
	}

	out := make([]CorrelatedAlertEntry, 0, len(b.entries))
	for _, e := range b.entries {
		if e.ID > afterID {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
