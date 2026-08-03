package domain

import "time"

// LiveEntry is one audit entry as shown by the dashboard's live activity
// view — an audit Entry plus a monotonically increasing ID assigned by
// the ring buffer, letting clients poll for "everything after ID N".
type LiveEntry struct {
	ID        int64
	Timestamp time.Time
	Identity  string
	Tenant    string
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
	Tenant    string `json:"tenant"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail"`
	Tool      string `json:"tool,omitempty"`
}

// CorrelatedAlertEntry is the dashboard's JSON view of one cross-instance
// correlated anomaly alert -- deliberately its own type (not a reuse of
// federation/usecase.CorrelatedAlertEntry) so the dashboard's JSON wire
// shape doesn't silently change if that usecase type's fields change for
// internal reasons, and so it gets a snake_case wire shape consistent
// with every other dashboard endpoint (AnomalyEntry above included),
// instead of the Go-cased fields encoding/json produces by default.
type CorrelatedAlertEntry struct {
	ID          int64    `json:"id"`
	Fingerprint string   `json:"fingerprint"`
	Kind        string   `json:"kind"`
	InstanceIDs []string `json:"instance_ids"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
}

// ReloadEntry is the dashboard's JSON view of one hot-reload attempt --
// deliberately its own type (not a reuse of reload.ReloadEvent), same
// rationale as AnomalyEntry/CorrelatedAlertEntry above: the dashboard's
// JSON wire shape must not silently change if platform/reload's internal
// type changes for its own reasons, and it gets a snake_case wire shape
// consistent with every other dashboard endpoint.
type ReloadEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	AppliedBy string `json:"applied_by"`
}
