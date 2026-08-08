package usecase

import (
	"sync"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

type blockEntry struct {
	since  time.Time
	until  time.Time
	reason string
	// tenant and identity recover the two parts of the map key for List's
	// output -- the key itself (tenantIdentityKey's opaque join) is not
	// reversible.
	tenant   string
	identity string
}

// expired reports whether e's TTL has already elapsed as of now -- the
// one expiry comparison Check, List, and GCBlocksOnce must all agree on,
// pulled out once so the three call sites can't silently drift apart.
func (e blockEntry) expired(now time.Time) bool {
	return !now.Before(e.until)
}

// BlockChecker tracks strictly time-bounded per-(tenant, identity) blocks,
// in-memory only. Satisfies Task 2's blocker interface (Block(identity,
// tenantName, reason string)) structurally -- Detector depends on that
// narrow interface, not on this concrete type.
type BlockChecker struct {
	cfg domain.AutoBlockConfig
	now func() time.Time

	mu sync.Mutex
	// blocked is keyed by tenantIdentityKey(tenant, identity), not by raw
	// identity -- see tenantIdentityKey's doc comment. Every read, write,
	// and iteration of this map must go through that same function.
	blocked map[string]blockEntry
}

func NewBlockChecker(cfg domain.AutoBlockConfig, now func() time.Time) *BlockChecker {
	return &BlockChecker{cfg: cfg, now: now, blocked: make(map[string]blockEntry)}
}

// Block records (identity, tenantName) as blocked for
// cfg.BlockDurationSeconds from now, with reason recorded for both the
// proxy's audit entry and the dashboard's blocked-list view.
func (b *BlockChecker) Block(identity, tenantName, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	since := b.now()
	until := since.Add(time.Duration(b.cfg.BlockDurationSeconds) * time.Second)
	b.blocked[tenantIdentityKey(tenantName, identity)] = blockEntry{since: since, until: until, reason: reason, tenant: tenantName, identity: identity}
}

// Check reports whether (identity, tenantName) may proceed at time now. A
// block whose TTL has already elapsed reads as "not blocked" without any
// separate invalidation step -- every call compares now against the
// stored until directly.
func (b *BlockChecker) Check(identity, tenantName string, now time.Time) domain.BlockVerdict {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.blocked[tenantIdentityKey(tenantName, identity)]
	if !ok || entry.expired(now) {
		return domain.BlockVerdict{Allowed: true}
	}
	return domain.BlockVerdict{Allowed: false, RetryAfter: entry.until.Sub(now), Reason: entry.reason}
}

// Unblock removes an active block for (identity, tenantName), if one
// exists, before its TTL would otherwise expire it. Returns whether an
// entry was actually present AND still active (not yet expired) --
// matching Check/List's own expired() comparison so all four readers of
// b.blocked agree on the same expiry semantics (see expired's doc
// comment). Not an error either way, matching this codebase's
// idempotent-delete convention elsewhere (e.g.
// scim.usecase.ProvisioningService.DeleteUser on an already-gone user).
func (b *BlockChecker) Unblock(identity, tenantName string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := tenantIdentityKey(tenantName, identity)
	e, ok := b.blocked[key]
	delete(b.blocked, key) // clean up regardless -- an expired entry is memory hygiene either way
	return ok && !e.expired(b.now())
}

// List returns every currently-blocked (tenant, identity) pair, filtered
// by TTL as of now -- an expired entry answers "not blocked" here exactly
// like it does in Check, rather than lingering in the dashboard's view for
// up to a full GC interval after it actually expired (StartBlockGC's
// interval is memory hygiene for the map, not a promise about what List
// shows). tenantFilter == "" means unfiltered (today's behavior, and the
// only behavior when rbac is off or the caller holds a global grant); a
// non-empty value drops every entry whose tenant doesn't match it
// exactly.
func (b *BlockChecker) List(tenantFilter string) []domain.BlockedEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	entries := make([]domain.BlockedEntry, 0, len(b.blocked))
	for _, e := range b.blocked {
		if e.expired(now) {
			continue
		}
		if tenantFilter != "" && e.tenant != tenantFilter {
			continue
		}
		entries = append(entries, domain.BlockedEntry{Identity: e.identity, Tenant: e.tenant, BlockedSince: e.since, BlockedUntil: e.until, Reason: e.reason})
	}
	return entries
}
