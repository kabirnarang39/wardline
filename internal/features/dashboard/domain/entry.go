package domain

import (
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// LiveEntry is one audit entry as shown by the dashboard's live activity
// view — an audit Entry plus a monotonically increasing ID assigned by
// the ring buffer, letting clients poll for "everything after ID N".
type LiveEntry struct {
	ID        int64
	Timestamp time.Time
	Identity  string
	Tool      string
	Decision  string
	LatencyMS int64
	Reason    string
	TraceID   string
}

// FromAuditEntry builds a LiveEntry from an audit.Entry and an ID
// assigned by the caller (the ring buffer, which owns ID allocation).
func FromAuditEntry(id int64, e auditdomain.Entry) LiveEntry {
	return LiveEntry{
		ID:        id,
		Timestamp: e.Timestamp,
		Identity:  e.Identity,
		Tool:      e.Tool,
		Decision:  e.Decision,
		LatencyMS: e.LatencyMS,
		Reason:    e.Reason,
		TraceID:   e.TraceID,
	}
}
