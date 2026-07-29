package usecase

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

type blockEntry struct {
	until  time.Time
	reason string
}

// expired reports whether e's TTL has already elapsed as of now -- the
// one expiry comparison Check, List, and GCBlocksOnce must all agree on,
// pulled out once so the three call sites can't silently drift apart.
func (e blockEntry) expired(now time.Time) bool {
	return !now.Before(e.until)
}

// BlockChecker tracks strictly time-bounded per-identity blocks,
// in-memory only. Satisfies Task 2's blocker interface (Block(identity,
// reason string)) structurally -- Detector depends on that narrow
// interface, not on this concrete type.
type BlockChecker struct {
	cfg domain.AutoBlockConfig
	now func() time.Time

	mu      sync.Mutex
	blocked map[string]blockEntry
}

func NewBlockChecker(cfg domain.AutoBlockConfig, now func() time.Time) *BlockChecker {
	return &BlockChecker{cfg: cfg, now: now, blocked: make(map[string]blockEntry)}
}

// Block records identity as blocked for cfg.BlockDurationSeconds from
// now, with reason recorded for both the proxy's audit entry and the
// dashboard's blocked-list view.
func (b *BlockChecker) Block(identity, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	until := b.now().Add(time.Duration(b.cfg.BlockDurationSeconds) * time.Second)
	b.blocked[identity] = blockEntry{until: until, reason: reason}
}

// Check reports whether identity may proceed at time now. A block whose
// TTL has already elapsed reads as "not blocked" without any separate
// invalidation step -- every call compares now against the stored
// until directly.
func (b *BlockChecker) Check(identity string, now time.Time) domain.BlockVerdict {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.blocked[identity]
	if !ok || entry.expired(now) {
		return domain.BlockVerdict{Allowed: true}
	}
	return domain.BlockVerdict{Allowed: false, RetryAfter: entry.until.Sub(now), Reason: entry.reason}
}

// List returns every currently-blocked identity, filtered by TTL as of
// now -- an expired entry answers "not blocked" here exactly like it
// does in Check, rather than lingering in the dashboard's view for up to
// a full GC interval after it actually expired (StartBlockGC's interval
// is memory hygiene for the map, not a promise about what List shows).
func (b *BlockChecker) List() []domain.BlockedEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	entries := make([]domain.BlockedEntry, 0, len(b.blocked))
	for identity, e := range b.blocked {
		if e.expired(now) {
			continue
		}
		entries = append(entries, domain.BlockedEntry{Identity: identity, BlockedUntil: e.until, Reason: e.reason})
	}
	return entries
}
