// Package domain holds the taint-tracking entities and the store interface.
// A taint label is a single, TTL'd integrity marker per (tenant, identity,
// session): set when an identity reads from an untrusted source, read
// synchronously into the policy decision context so a rule can deny or route a
// subsequent write. stdlib-only, no I/O.
package domain

import "time"

// Label is the integrity taint state for one keyed (tenant, identity,
// session). The zero value is untainted. Sources is unused in Phase 1 —
// present so Phase 2 can carry multi-source provenance without reshaping the
// stored value.
type Label struct {
	Tainted bool
	SetAt   time.Time
	Sources []string
}

// TaintContext pairs a store key with its label. Returned by iteration; the
// engine and policy read path work in terms of it rather than a bare
// (key, Label) tuple so Phase 2 can attach more per-key metadata.
type TaintContext struct {
	Key   string
	Label Label
}

// TaintStore persists labels by key. Implementations must be safe for
// concurrent use: the taint engine writes from the live audit stream while the
// policy path reads synchronously at decision time.
type TaintStore interface {
	Get(key string) (Label, bool)
	Set(key string, l Label)
	Clear(key string)
}

// Clock supplies the current time. Injected so tests drive TTL expiry without
// real sleeps.
type Clock func() time.Time
