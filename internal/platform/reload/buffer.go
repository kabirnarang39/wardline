package reload

import "sync"

// ReloadEvent is a ReloadResult plus a monotonic ID assigned by
// ReloadEventBuffer, giving API consumers (the dashboard's
// /dashboard/api/reload/history) the same after-ID pagination shape as
// the audit ring buffer's LiveEntry and anomaly/usecase.AlertBuffer's
// Alert.
type ReloadEvent struct {
	ID int64
	ReloadResult
}

// ReloadEventBuffer is a bounded, in-memory, most-recent-N store of
// ReloadEvent values -- mirrors anomaly/usecase.AlertBuffer's shape
// exactly (see that type's doc comment for why this codebase keeps
// per-feature ring buffers rather than sharing one generic type: this
// package's own coordinator.go doc explains reload events must NOT share
// the audit/domain.Entry stream, for the same "a second, differently-
// shaped event type corrupts consumers' assumptions" reason AlertBuffer
// already exists to avoid for anomalies). Safe for concurrent use.
type ReloadEventBuffer struct {
	mu      sync.Mutex
	cap     int
	entries []ReloadEvent
	nextID  int64
}

func NewReloadEventBuffer(capacity int) *ReloadEventBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &ReloadEventBuffer{cap: capacity, entries: make([]ReloadEvent, 0, capacity)}
}

// Add records a reload attempt's outcome (success or rejection alike --
// see ReloadCoordinator.OnAudit, which calls this on both paths),
// evicting the oldest entry once capacity is reached.
func (b *ReloadEventBuffer) Add(r ReloadResult) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	entry := ReloadEvent{ID: b.nextID, ReloadResult: r}

	if len(b.entries) >= b.cap {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

// Since returns entries with ID > afterID, oldest first, capped to the
// most recent limit of them (afterID=0 means "from the start"; limit <=
// 0 means no cap). Identical semantics to AlertBuffer.Since, including
// the same restart handling: an afterID ahead of nextID (Wardline
// restarted since the client last polled) is treated as "from the
// start". Unlike AlertBuffer.Since there is no tenantFilter parameter --
// reload events are process-wide config operations, not tenant-scoped
// data, so there is nothing to filter by (same reasoning as
// federation/usecase.CorrelatedAlertBuffer.Since, which also takes only
// afterID and limit).
func (b *ReloadEventBuffer) Since(afterID int64, limit int) []ReloadEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	if afterID > b.nextID {
		afterID = 0
	}

	out := make([]ReloadEvent, 0, len(b.entries))
	for _, e := range b.entries {
		if e.ID <= afterID {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
