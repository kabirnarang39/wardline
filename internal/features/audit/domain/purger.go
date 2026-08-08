package domain

import (
	"context"
	"time"
)

// Purger deletes audit entries older than cutoff -- the retention
// counterpart to Reader's query capability. Returns how many entries
// were actually removed, so a caller can log a meaningful count rather
// than a bare "done".
type Purger interface {
	Purge(ctx context.Context, cutoff time.Time) (int, error)
}
