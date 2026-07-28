package domain

import "time"

// Manifest is the compliance evidence bundle's own metadata -- what's
// inside the bundle and how/when it was produced. Features is the same
// bool map already exposed unauthenticated via the dashboard's
// /dashboard/api/status, so including it here discloses nothing new.
type Manifest struct {
	WardlineVersion             string          `json:"wardline_version"`
	GeneratedAt                 time.Time       `json:"generated_at"`
	RangeFrom                   time.Time       `json:"range_from"`
	RangeTo                     time.Time       `json:"range_to"`
	Features                    map[string]bool `json:"features"`
	AuditEntryCount             int             `json:"audit_entry_count"`
	AuditDecisionCounts         map[string]int  `json:"audit_decision_counts"`
	UnparsableAuditLinesSkipped int             `json:"unparsable_audit_lines_skipped"`
	AnomalyEntryCount           int             `json:"anomaly_entry_count"`
	AnomalyKindCounts           map[string]int  `json:"anomaly_kind_counts"`

	// UnparsableAnomalyLinesSkipped is the anomaly stream's counterpart to
	// UnparsableAuditLinesSkipped. Both exist so a skipped line shows up as
	// a declared gap in the evidence rather than silently shrinking the
	// bundle -- an auditor must be able to see that something was dropped.
	UnparsableAnomalyLinesSkipped int `json:"unparsable_anomaly_lines_skipped"`
}
