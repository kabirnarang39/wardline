package usecase

import (
	"sync"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
)

// RingBuffer is a bounded, in-memory, most-recent-N store of LiveEntry
// values. It implements audit/domain.LiveSink: every Recorder.Record call
// (when the web_ui flag is on) publishes here in addition to the durable
// audit log, giving the dashboard a live view that's cheap to read and
// empty again after a restart — the JSONL file remains the durable
// record. Safe for concurrent use.
type RingBuffer struct {
	mu      sync.Mutex
	cap     int
	entries []domain.LiveEntry
	nextID  int64
}

var _ auditdomain.LiveSink = (*RingBuffer)(nil)

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &RingBuffer{
		cap:     capacity,
		entries: make([]domain.LiveEntry, 0, capacity),
	}
}

// Publish implements audit/domain.LiveSink. It assigns the next
// monotonic ID and appends, evicting the oldest entry first if the
// buffer is already at capacity.
func (b *RingBuffer) Publish(e auditdomain.Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	entry := domain.FromAuditEntry(b.nextID, e)

	if len(b.entries) >= b.cap {
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

// Since returns entries with ID > afterID, oldest first, capped to the
// most recent `limit` of them (afterID=0 means "from the start" — used
// for a client's initial load; a positive afterID is used for polling
// "what's new since I last asked"). limit <= 0 means no cap.
func (b *RingBuffer) Since(afterID int64, limit int) []domain.LiveEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]domain.LiveEntry, 0, len(b.entries))
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
