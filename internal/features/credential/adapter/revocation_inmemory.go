package adapter

import (
	"sync"
	"time"
)

// revocationEvictionSweepInterval mirrors budget.InMemoryLimiter's
// evictionSweepInterval — an opportunistic full-map sweep every N calls,
// piggybacked on IsRevoked rather than a dedicated cleanup goroutine.
const revocationEvictionSweepInterval = 1000

// RevocationList is a domain.Revoker backed by a per-identity expiry map
// held in process memory — same single-process scope and
// eviction-sweep-on-access pattern as budget's InMemoryLimiter, and the
// same multi-replica-shared-state limitation (see design doc "Out of
// scope").
type RevocationList struct {
	mu      sync.Mutex
	entries map[string]time.Time
	calls   uint64
	now     func() time.Time
}

func NewRevocationList() *RevocationList {
	return &RevocationList{entries: make(map[string]time.Time), now: time.Now}
}

func (r *RevocationList) Revoke(identity string, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[identity] = expiresAt
}

func (r *RevocationList) IsRevoked(identity string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls++
	if r.calls%revocationEvictionSweepInterval == 0 {
		r.evictExpired()
	}

	expiresAt, ok := r.entries[identity]
	if !ok {
		return false
	}
	if r.now().After(expiresAt) {
		delete(r.entries, identity) // self-heal: don't wait for the periodic sweep
		return false
	}
	return true
}

// evictExpired deletes entries whose expiry has already passed. Called
// with r.mu already held.
func (r *RevocationList) evictExpired() {
	now := r.now()
	for id, exp := range r.entries {
		if now.After(exp) {
			delete(r.entries, id)
		}
	}
}
