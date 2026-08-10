// Package adapter holds concrete taint infrastructure — the in-memory
// TaintStore today, a Postgres-backed one later.
package adapter

import (
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/taint/domain"
)

// InMemoryStore is a mutex-guarded map satisfying domain.TaintStore. The taint
// engine writes from the live audit stream while the policy path reads
// synchronously at decision time, so every access takes the lock.
//
// ponytail: a single global mutex over one map. Taint reads/writes are a few
// per request and the map is small (live sessions only, TTL-bounded), so lock
// contention is a non-issue; shard by key only if a profile ever shows this
// mutex hot.
type InMemoryStore struct {
	mu sync.Mutex
	m  map[string]domain.Label
}

// NewInMemoryStore returns an empty, ready-to-use store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{m: make(map[string]domain.Label)}
}

func (s *InMemoryStore) Get(key string) (domain.Label, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.m[key]
	return l, ok
}

func (s *InMemoryStore) Set(key string, l domain.Label) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = l
}

func (s *InMemoryStore) Clear(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}
