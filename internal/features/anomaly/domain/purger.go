package domain

import (
	"context"
	"time"
)

// Purger deletes anomaly entries older than cutoff. Mirrors
// audit/domain.Purger -- see that type's doc comment.
type Purger interface {
	Purge(ctx context.Context, cutoff time.Time) (int, error)
}
