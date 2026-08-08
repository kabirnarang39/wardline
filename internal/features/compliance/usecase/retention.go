package usecase

import (
	"context"
	"time"
)

// NamedPurger pairs a Purge function (audit/domain.Purger's or
// anomaly/domain.Purger's Purge method, both the identical
// `func(ctx, cutoff) (int, error)` shape) with a human-readable name for
// logging and its own configured RetentionDays -- RunRetention stays
// generic over which concrete store it drives without importing either
// feature's domain package here.
type NamedPurger struct {
	Name          string
	RetentionDays int
	Purge         func(ctx context.Context, cutoff time.Time) (int, error)
}

// RetentionResult is one purger's outcome for a single retention tick.
type RetentionResult struct {
	Name    string
	Cutoff  time.Time
	Deleted int
	Err     error
}

// RunRetention purges every purger whose RetentionDays > 0, computing
// each one's own cutoff from now. A purger with RetentionDays <= 0 is
// skipped entirely (not even a zero-Deleted result), matching the
// "0 means keep forever" config convention. Each purger runs
// independently -- one failing Purge call must not block the others in
// the same tick; the caller inspects each RetentionResult.Err rather
// than this function returning early on the first error.
func RunRetention(ctx context.Context, purgers []NamedPurger, now time.Time) []RetentionResult {
	var results []RetentionResult
	for _, p := range purgers {
		if p.RetentionDays <= 0 {
			continue
		}
		cutoff := now.AddDate(0, 0, -p.RetentionDays)
		deleted, err := p.Purge(ctx, cutoff)
		results = append(results, RetentionResult{Name: p.Name, Cutoff: cutoff, Deleted: deleted, Err: err})
	}
	return results
}
