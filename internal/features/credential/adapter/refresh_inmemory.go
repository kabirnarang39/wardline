package adapter

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// refreshEntry is one issued refresh token's server-side state. A
// consumed entry is kept (not deleted) until it expires so a later
// replay of it is detectable as reuse; family ties every entry to its
// bootstrap lineage so a reused token can revoke the whole chain.
type refreshEntry struct {
	identity  string
	tenant    string
	family    string
	expiresAt time.Time
	consumed  bool
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

func (s *InMemoryRefreshStore) Issue(token, identity, tenantName, family string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byTok[token] = refreshEntry{identity: identity, tenant: tenantName, family: family, expiresAt: expiresAt}
	return nil
}

// Redeem implements the reuse-detecting state machine (see
// domain.RefreshStore): an active token is marked consumed and returned;
// replaying an already-consumed token revokes its whole family and
// returns ErrRefreshTokenReused; an unknown or expired token returns
// ErrRefreshTokenInvalid. All under s.mu, so the whole transition is
// atomic against concurrent redeems in this process (this store is
// single-process by construction).
func (s *InMemoryRefreshStore) Redeem(token string) (string, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls++
	if s.calls%revocationEvictionSweepInterval == 0 {
		s.evictExpired()
	}

	entry, ok := s.byTok[token]
	if !ok {
		return "", "", "", domain.ErrRefreshTokenInvalid
	}
	if entry.consumed {
		// Reuse of a consumed token: theft signal. Wipe the whole family
		// -- the legitimate current token in this lineage dies with the
		// attacker's replayed one.
		s.revokeFamilyLocked(entry.family)
		return "", "", "", domain.ErrRefreshTokenReused
	}
	if s.now().After(entry.expiresAt) {
		delete(s.byTok, token)
		return "", "", "", domain.ErrRefreshTokenInvalid
	}
	// Mark consumed but keep it -- a later replay must be detectable as
	// reuse, not indistinguishable from "never existed".
	entry.consumed = true
	s.byTok[token] = entry
	return entry.identity, entry.tenant, entry.family, nil
}

// revokeFamilyLocked deletes every token sharing the given family.
// Called with s.mu already held.
func (s *InMemoryRefreshStore) revokeFamilyLocked(family string) {
	for tok, entry := range s.byTok {
		if entry.family == family {
			delete(s.byTok, tok)
		}
	}
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
