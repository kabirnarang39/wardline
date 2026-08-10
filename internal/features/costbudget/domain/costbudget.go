// Package domain holds the per-job cost/token budget's entities and Meter
// interface. A "job" is a (tenant, identity, session) triple, the same
// session concept jobbudget and taint tracking use. Unlike jobbudget.Meter
// (which increments by exactly 1 per call), this Meter accumulates a
// per-call amount -- a deliberately separate interface, not a widened
// jobbudget.Meter, so already-shipped request-count code stays untouched.
// See docs/superpowers/specs/2026-08-11-cost-budget-design.md §A.
package domain

import "time"

// Meter accumulates cost/token amounts per job key.
type Meter interface {
	// Add records amount against key and returns the new running total.
	// Called exactly once per gated request, by the hard-gate check only
	// (see costbudget/usecase.Checker.Check) -- never called from the
	// policy-exposure read path, which must not have a side effect.
	Add(key string, amount int, now time.Time) (total int, err error)

	// Current reads key's running total without adding to it. A
	// never-seen key returns (0, nil), not an error. Used by the
	// policy-exposure read path (Checker.IsOverBudget), which runs during
	// policy Decide -- before the hard gate has added for this request --
	// so it must reflect prior calls only, never this one.
	Current(key string, now time.Time) (total int, err error)
}

// Verdict is the result of checking whether a job may spend amount more.
type Verdict struct {
	Allowed bool
	Reason  string
	Total   int

	// FailedOpen marks an Allowed verdict granted without the ceiling
	// actually being checked, because a Postgres-backed Meter hit a
	// genuine backend error and chose availability over enforcement.
	// Mirrors jobbudget.Verdict.FailedOpen / budget.Verdict.FailedOpen.
	FailedOpen bool
}
