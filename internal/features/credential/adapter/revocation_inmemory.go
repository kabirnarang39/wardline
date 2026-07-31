package adapter

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// revocationEvictionSweepInterval mirrors budget.InMemoryLimiter's
// evictionSweepInterval — an opportunistic full-map sweep every N calls,
// piggybacked on IsRevoked rather than a dedicated cleanup goroutine.
const revocationEvictionSweepInterval = 1000

// RevocationList is a domain.Revoker backed by a per-(tenant,identity)
// expiry map held in process memory — same single-process scope and
// eviction-sweep-on-access pattern as budget's InMemoryLimiter, and the
// same multi-replica-shared-state limitation (see design doc "Out of
// scope"). entries is keyed by tenant.Key(tenantName, identity) for a
// scoped revoke, or bare identity for a wildcard revoke (tenantName ==
// "" at Revoke time, or a legacy row written before this keying
// existed) -- IsRevoked always checks both shapes.
type RevocationList struct {
	mu      sync.Mutex
	entries map[string]time.Time
	calls   uint64
	now     func() time.Time
}

func NewRevocationList() *RevocationList {
	return &RevocationList{entries: make(map[string]time.Time), now: time.Now}
}

func (r *RevocationList) Revoke(tenantName, identity string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := identity
	if tenantName != "" {
		key = tenant.Key(tenantName, identity)
	}
	r.entries[key] = expiresAt
	return nil
}

func (r *RevocationList) IsRevoked(tenantName, identity string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls++
	if r.calls%revocationEvictionSweepInterval == 0 {
		r.evictExpired()
	}

	if tenantName != "" {
		if r.checkAndSelfHeal(tenant.Key(tenantName, identity)) {
			return true
		}
	}
	return r.checkAndSelfHeal(identity) // wildcard / legacy shape
}

// checkAndSelfHeal reports whether key is currently revoked, deleting
// an expired entry on the way out instead of waiting for the periodic
// sweep. Called with r.mu already held.
func (r *RevocationList) checkAndSelfHeal(key string) bool {
	expiresAt, ok := r.entries[key]
	if !ok {
		return false
	}
	if r.now().After(expiresAt) {
		delete(r.entries, key)
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
