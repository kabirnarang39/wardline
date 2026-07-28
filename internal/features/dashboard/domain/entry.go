package domain

import "time"

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

// AnomalyEntry is the dashboard's JSON view of one flagged anomaly --
// deliberately its own type (not a reuse of anomaly/usecase.Alert)
// so the dashboard's JSON wire shape doesn't silently change if that
// usecase type's fields change for internal reasons.
type AnomalyEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Identity  string `json:"identity"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
	Tool      string `json:"tool,omitempty"`
}
