// Package adapter holds concrete jobbudget infrastructure -- the
// in-memory Meter today, a Postgres-backed one for cross-replica sharing.
package adapter

import (
	"sort"
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
)

// InMemoryMeter is a mutex-guarded map[string]int satisfying domain.Meter.
// ponytail: single global mutex; job-budget increments are one per gated
// call, same order of magnitude as taint's store, so contention is a
// non-issue. Shard only if a profile ever shows this mutex hot.
type InMemoryMeter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewInMemoryMeter() *InMemoryMeter {
	return &InMemoryMeter{counts: make(map[string]int)}
}

func (m *InMemoryMeter) Increment(key string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[key]++
	return m.counts[key], nil
}

func (m *InMemoryMeter) Current(key string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[key], nil // zero value for an absent key, no separate "ok" needed
}

// ListNearCeiling satisfies domain.Lister -- an optional, dashboard-only
// capability, not part of Meter itself (see domain.Lister's doc comment).
// Returns up to limit entries, ordered by count descending.
func (m *InMemoryMeter) ListNearCeiling(limit int) []domain.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]domain.Entry, 0, len(m.counts))
	for k, c := range m.counts {
		entries = append(entries, domain.Entry{Key: k, Count: c})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })
	if limit >= 0 && limit < len(entries) {
		entries = entries[:limit]
	}
	return entries
}
