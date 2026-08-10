// Package domain holds the per-job budget ceiling's entities and Meter
// interface. A "job" is a (tenant, identity, session) triple, the same
// session concept taint tracking uses (see internal/platform/session).
package domain

import "time"

// Meter counts calls per job key. Open/Closed seam: a token/cost Meter
// implementation slots in later behind this same interface, zero changes
// to the Checker that consumes it.
type Meter interface {
	// Increment records one call against key and returns the new total.
	// Called exactly once per gated request, by the hard-gate check only
	// (see jobbudget/usecase.Checker.Check) -- never called from the
	// policy-exposure read path, which must not have a side effect.
	Increment(key string, now time.Time) (count int, err error)

	// Current reads key's running count without incrementing it. A
	// never-seen key returns (0, nil), not an error. Used by the
	// policy-exposure read path (Checker.IsOverBudget), which runs during
	// policy Decide -- before the hard gate has incremented for this
	// request -- so it must reflect prior calls only, never this one.
	Current(key string, now time.Time) (count int, err error)
}

// Verdict is the result of checking whether a job may make another call.
type Verdict struct {
	Allowed bool
	Reason  string
	Count   int

	// FailedOpen marks an Allowed verdict granted without the ceiling
	// actually being checked, because a Postgres-backed Meter hit a
	// genuine backend error and chose availability over enforcement. Only
	// ever true alongside Allowed — mirrors budget.Verdict.FailedOpen
	// exactly, same rationale: a skipped check must leave a durable audit
	// trace, not just a Warn log line.
	FailedOpen bool
}
