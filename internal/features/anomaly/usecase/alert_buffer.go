package usecase

import (
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// Alert is a domain.Anomaly plus a monotonic ID assigned by AlertBuffer,
// giving API consumers (the dashboard's /dashboard/api/anomalies) the
// same after-ID pagination shape as the audit ring buffer's LiveEntry.
type Alert struct {
	ID int64
	domain.Anomaly
}

// AlertBuffer is a bounded, in-memory, most-recent-N store of Alert
// values -- structurally identical to dashboard/usecase.RingBuffer,
// kept as its own type in this feature (not shared) per this codebase's
// per-feature vertical-slice convention: the two ring buffers store
// different element types for different reasons, and sharing one
// generic ring type across two features would couple them for no
// benefit. Safe for concurrent use.
type AlertBuffer struct {
	mu      sync.Mutex
	cap     int
	entries []Alert
	nextID  int64
}

func NewAlertBuffer(capacity int) *AlertBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &AlertBuffer{cap: capacity, entries: make([]Alert, 0, capacity)}
}

// Add implements the alertSink interface Detector depends on (Task 3).
func (b *AlertBuffer) Add(a domain.Anomaly) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	entry := Alert{ID: b.nextID, Anomaly: a}

	if len(b.entries) >= b.cap {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

// Since returns entries with ID > afterID, oldest first, capped to the
// most recent limit of them (afterID=0 means "from the start"; limit <=
// 0 means no cap). Identical semantics to
// dashboard/usecase.RingBuffer.Since, including the same restart
// handling: an afterID ahead of nextID (Wardline restarted since the
// client last polled) is treated as "from the start". tenantFilter == ""
// means unfiltered (federation's Publisher, which aggregates every local
// tenant's anomalies for cross-instance summaries, always passes "";
// the dashboard's AnomalySource passes the RBAC-resolved caller's own
// tenant, or "" for a globally-granted caller) -- a non-empty value
// drops every entry whose Tenant doesn't match it exactly.
func (b *AlertBuffer) Since(afterID int64, limit int, tenantFilter string) []Alert {
	b.mu.Lock()
	defer b.mu.Unlock()

	if afterID > b.nextID {
		afterID = 0
	}

	out := make([]Alert, 0, len(b.entries))
	for _, e := range b.entries {
		if e.ID <= afterID {
			continue
		}
		if tenantFilter != "" && e.Tenant != tenantFilter {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
