package adapter

import (
	"sort"
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
)

// InMemoryMeter is a mutex-guarded map[string]int satisfying domain.Meter.
// ponytail: single global mutex; cost-budget adds are one per gated call,
// same order of magnitude as jobbudget's store. Shard only if a profile
// ever shows this mutex hot.
type InMemoryMeter struct {
	mu     sync.Mutex
	totals map[string]int
}

func NewInMemoryMeter() *InMemoryMeter {
	return &InMemoryMeter{totals: make(map[string]int)}
}

func (m *InMemoryMeter) Add(key string, amount int, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totals[key] += amount
	return m.totals[key], nil
}

func (m *InMemoryMeter) Current(key string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totals[key], nil
}

// ListNearCeiling satisfies domain.Lister. limit <= 0 returns no entries --
// matches PostgresMeter's behavior for the same input (see that adapter).
func (m *InMemoryMeter) ListNearCeiling(limit int) []domain.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]domain.Entry, 0, len(m.totals))
	for k, t := range m.totals {
		entries = append(entries, domain.Entry{Key: k, Total: t})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Total > entries[j].Total })
	if limit <= 0 {
		return []domain.Entry{}
	}
	if limit < len(entries) {
		entries = entries[:limit]
	}
	return entries
}
