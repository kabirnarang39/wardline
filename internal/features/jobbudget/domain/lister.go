package domain

// Lister is an optional capability a Meter MAY implement, for the
// dashboard's read-only job-budget view. Not part of Meter itself --
// widening Meter would force every Meter implementation (including a
// future token/cost one) to support enumeration, which isn't required
// for the core Checker to function. Entries carry the opaque job key and
// its running count -- the key's tenant/identity/session are NOT
// decomposed for display (the length-prefixed key format is one-way by
// design), a known, documented limitation.
type Lister interface {
	// ListNearCeiling returns up to limit job entries, ordered by count
	// descending -- the callers nearest their ceiling first.
	ListNearCeiling(limit int) []Entry
}

// Entry is one job key's running count, as read by Lister.
type Entry struct {
	Key   string
	Count int
}
