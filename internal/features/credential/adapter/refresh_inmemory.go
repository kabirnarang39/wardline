package adapter

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// refreshEntry is one issued-but-not-yet-redeemed refresh token's
// server-side state.
type refreshEntry struct {
	identity  string
	tenant    string
	expiresAt time.Time
}

// InMemoryRefreshStore is a domain.RefreshStore backed by a token->entry
// map held in process memory -- same single-process scope and
// eviction-sweep-on-access pattern as RevocationList (see
// revocation_inmemory.go), reusing its revocationEvictionSweepInterval
// constant directly (same package, same tuning value: an opportunistic
// full-map sweep every 1000 calls, piggybacked on Redeem rather than a
// dedicated cleanup goroutine).
//
// Unlike RevocationList (keyed by (tenant, identity), one entry per
// identity), this map is keyed by the opaque token value, with
// (tenant, identity) stored as payload -- a single identity can have
// many outstanding refresh tokens issued at different times, and
// RevokeAllForIdentity has to find and delete every one of them. There
// is no secondary index by identity: RevokeAllForIdentity does a full
// O(n) scan of byTok instead (see its own doc comment), acceptable at
// this store's expected scale the same way RevocationList's
// evictExpired already does a full-map scan.
type InMemoryRefreshStore struct {
	mu    sync.Mutex
	byTok map[string]refreshEntry
	calls uint64
	now   func() time.Time
}

func NewInMemoryRefreshStore() *InMemoryRefreshStore {
	return &InMemoryRefreshStore{byTok: make(map[string]refreshEntry), now: time.Now}
}

func (s *InMemoryRefreshStore) Issue(token, identity, tenantName string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byTok[token] = refreshEntry{identity: identity, tenant: tenantName, expiresAt: expiresAt}
	return nil
}

// Redeem deletes the entry unconditionally once found (whether or not
// it's expired) -- an expired-but-not-yet-swept entry must never be
// redeemable, and deleting it here rather than leaving it for the
// periodic sweep is itself a form of self-healing, same as
// RevocationList.checkAndSelfHeal.
func (s *InMemoryRefreshStore) Redeem(token string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls++
	if s.calls%revocationEvictionSweepInterval == 0 {
		s.evictExpired()
	}

	entry, ok := s.byTok[token]
	if !ok {
		return "", "", domain.ErrRefreshTokenInvalid
	}
	delete(s.byTok, token)
	if s.now().After(entry.expiresAt) {
		return "", "", domain.ErrRefreshTokenInvalid
	}
	return entry.identity, entry.tenant, nil
}

// RevokeAllForIdentity scans the full map for every entry matching
// (tenantName, identity) and deletes them -- an O(n) scan over
// outstanding refresh tokens, acceptable at this store's expected scale
// (one process's in-memory refresh tokens, evicted regularly) the same
// way RevocationList's evictExpired already does a full-map scan.
// tenantName == "" matches every tenant for this identity (the wildcard
// convention domain.Revoker already established) -- mirrors
// RevocationList's own wildcard-or-scoped dual-key check, adapted for a
// scan since this store has no single lookup key per identity.
func (s *InMemoryRefreshStore) RevokeAllForIdentity(tenantName, identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, entry := range s.byTok {
		if entry.identity != identity {
			continue
		}
		if tenantName == "" || entry.tenant == tenantName {
			delete(s.byTok, tok)
		}
	}
	return nil
}

// evictExpired deletes entries whose expiry has already passed. Called
// with s.mu already held.
func (s *InMemoryRefreshStore) evictExpired() {
	now := s.now()
	for tok, entry := range s.byTok {
		if now.After(entry.expiresAt) {
			delete(s.byTok, tok)
		}
	}
}

var _ domain.RefreshStore = (*InMemoryRefreshStore)(nil)
