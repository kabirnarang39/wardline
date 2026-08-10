// Package adapter holds concrete jobbudget infrastructure -- the
// in-memory Meter today, a Postgres-backed one for cross-replica sharing.
package adapter

import (
	"sync"
	"time"
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
