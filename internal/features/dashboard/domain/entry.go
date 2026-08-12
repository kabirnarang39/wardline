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
	// Score is the detector's own magnitude, omitted (not zero) for a
	// kind with no real score to report -- see anomalydomain.Anomaly.Score's
	// own doc comment for why nil must never become a fabricated 0.
	Score *float64 `json:"score,omitempty"`
	// AutoBlockSeconds is real auto-block duration if THIS anomaly caused
	// one, 0 otherwise -- omitted from JSON at 0 via omitempty, same
	// "absence over a fabricated placeholder" posture as Score.
	AutoBlockSeconds int `json:"auto_block_seconds,omitempty"`
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
	Tenant      string   `json:"tenant"`
	Kind        string   `json:"kind"`
	InstanceIDs []string `json:"instance_ids"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
}

// RoleEntry is the dashboard's JSON view of one rbac.Role -- deliberately
// its own type (not a reuse of rbac/domain.Role), same reasoning as
// AnomalyEntry/CorrelatedAlertEntry above.
type RoleEntry struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	// BindingCount is computed by the handler (not stored on Role
	// itself) -- how many cluster+role bindings reference this role.
	BindingCount int `json:"binding_count"`
}

// BindingEntry is the dashboard's JSON view of one binding -- either a
// rbac/domain.ClusterRoleBinding (Tenant left empty) or a
// rbac/domain.RoleBinding (Tenant set).
type BindingEntry struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
	// Tenant is empty for a cluster-scoped (global) binding.
	Tenant string `json:"tenant"`
}

// BudgetDefaultEntry is the dashboard's JSON view of the global
// (non-override) rate limit -- deliberately its own type (not a reuse of
// budgetdomain.LimitInfo), same reasoning as AnomalyEntry/BindingEntry
// above, and so it gets this file's snake_case wire convention instead of
// encoding/json's default Go-cased fields.
type BudgetDefaultEntry struct {
	RequestsPerWindow int `json:"requests_per_window"`
	WindowSeconds     int `json:"window_seconds"`
}

// BudgetOverrideEntry is the dashboard's JSON view of one tenant or tool
// rate-limit override -- deliberately its own type, same reasoning as
// BudgetDefaultEntry above.
type BudgetOverrideEntry struct {
	Scope             string `json:"scope"`
	Name              string `json:"name"`
	RequestsPerWindow int    `json:"requests_per_window"`
	WindowSeconds     int    `json:"window_seconds"`
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
