package adapter

import (
	"fmt"
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
)

// InMemoryStore satisfies domain.Store with two mutex-guarded maps.
// ponytail: single global mutex; approval volume is low (human-paced), so
// contention is a non-issue. Shard only if a profile ever shows this hot.
type InMemoryStore struct {
	mu       sync.Mutex
	requests map[string]domain.Request
	grants   map[string]domain.Grant
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{requests: map[string]domain.Request{}, grants: map[string]domain.Grant{}}
}

func (s *InMemoryStore) CreateRequest(r domain.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.requests[r.ID]; exists {
		return fmt.Errorf("approval request %q already exists", r.ID)
	}
	s.requests[r.ID] = r
	return nil
}

func (s *InMemoryStore) GetRequest(id string) (domain.Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	return r, ok
}

func (s *InMemoryStore) ListPending(tenant string) []domain.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.Request
	for _, r := range s.requests {
		if r.Status == domain.StatusPending && (tenant == "" || r.Tenant == tenant) {
			out = append(out, r)
		}
	}
	return out
}

func (s *InMemoryStore) DecideRequest(id string, status domain.Status, decidedBy string, now time.Time) (domain.Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.requests[id]
	if !ok {
		return domain.Request{}, fmt.Errorf("approval request %q not found", id)
	}
	if r.Status != domain.StatusPending {
		return domain.Request{}, fmt.Errorf("approval request %q already %s", id, r.Status)
	}
	r.Status = status
	r.DecidedBy = decidedBy
	r.DecidedAt = now
	s.requests[id] = r
	return r, nil
}

func (s *InMemoryStore) PutGrant(g domain.Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[g.Key] = g
}

func (s *InMemoryStore) ConsumeGrant(key string, now time.Time) (domain.Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[key]
	if !ok {
		return domain.Grant{}, false
	}
	delete(s.grants, key) // single-use: gone whether or not it was valid
	if now.After(g.ExpiresAt) {
		return domain.Grant{}, false
	}
	return g, true
}
