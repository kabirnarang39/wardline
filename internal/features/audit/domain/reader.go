package domain

import (
	"context"
	"time"
)

// Reader queries durable audit history for entries with Timestamp in
// [from, to) -- the read-side counterpart to Writer, needed for
// compliance evidence export (Writer alone is append-only; nothing in
// Wardline could previously read audit history back).
type Reader interface {
	Query(ctx context.Context, from, to time.Time) ([]Entry, error)
}
