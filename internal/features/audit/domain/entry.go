package domain

import "time"

// Entry is one audit record: what identity tried to call what tool, and
// what happened.
type Entry struct {
	Timestamp time.Time
	Identity  string
	Tool      string
	Decision  string // "allow", "deny", or "error"
	LatencyMS int64

	// Reason is the detailed, potentially sensitive explanation behind a
	// decision (e.g. a policy engine's internal error text, file paths,
	// or rule names). It's recorded here for the operator only — never
	// sent to the untrusted HTTP caller.
	Reason string
}

// Writer persists an audit Entry.
type Writer interface {
	Write(Entry) error
}
