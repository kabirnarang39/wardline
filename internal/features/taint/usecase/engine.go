package usecase

import (
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/taint/domain"
)

// Engine sets, expires, and declassifies taint labels. It consumes the live
// audit stream as a LiveSink to *set* taint out-of-band, and exposes a cheap
// synchronous *read* (Current) for the policy decision path. It never blocks
// or errors outward — the LiveSink contract.
//
// Session derivation uses the fallback TTL window in Phase 1: the audit Entry
// carries no session header, so both the set path (Publish, keyed on the
// entry's timestamp) and the read path (Current, keyed on now) bucket by the
// same window. The header-wins branch in SessionID is exercised at the read
// site when a caller supplies one, ready for Phase 2 when the session id is
// plumbed onto the Entry.
type Engine struct {
	cfg        domain.TaintConfig
	store      domain.TaintStore
	clock      domain.Clock
	untrusted  map[string]struct{}
	declassify map[string]struct{}
}

// NewEngine builds a taint engine. The untrusted/declassify source lists are
// pre-indexed into sets for O(1) lookup on the hot Publish path.
func NewEngine(cfg domain.TaintConfig, store domain.TaintStore, clock domain.Clock) *Engine {
	return &Engine{
		cfg:        cfg,
		store:      store,
		clock:      clock,
		untrusted:  toSet(cfg.UntrustedSources),
		declassify: toSet(cfg.DeclassifySources),
	}
}

func toSet(xs []string) map[string]struct{} {
	s := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		s[x] = struct{}{}
	}
	return s
}

// Publish inspects one audit entry: a call to an untrusted source taints the
// (tenant, identity, session); a declassifying call clears it. Any other call
// is ignored. Implements audit/domain.LiveSink.
func (e *Engine) Publish(entry auditdomain.Entry) {
	// Only successful/attempted calls matter; a denied or blocked call never
	// reached the untrusted source, so it cannot have tainted the identity.
	if entry.Decision == "deny" || entry.Decision == "blocked" || entry.Decision == "throttled" {
		return
	}
	session := SessionID(entry.SessionID, entry.Tenant, entry.Identity, entry.Timestamp, e.cfg.Window())
	key := taintKey(entry.Tenant, entry.Identity, session)

	if _, ok := e.declassify[entry.Tool]; ok {
		e.store.Clear(key)
		return
	}
	if _, ok := e.untrusted[entry.Tool]; ok {
		e.store.Set(key, domain.Label{Tainted: true, SetAt: entry.Timestamp, Sources: []string{entry.Tool}})
	}
}

// Current reports the live taint label for a (tenant, identity, session),
// applying TTL expiry lazily: a label past SetAt+TTL reads as untainted
// without a background sweep. The synchronous read the policy path uses.
func (e *Engine) Current(tenant, identity, session string, now time.Time) domain.Label {
	key := taintKey(tenant, identity, session)
	l, ok := e.store.Get(key)
	if !ok || !l.Tainted {
		return domain.Label{}
	}
	if now.After(l.SetAt.Add(time.Duration(e.cfg.TTL()) * time.Second)) {
		return domain.Label{}
	}
	return l
}
