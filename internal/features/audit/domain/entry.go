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
}

// Writer persists an audit Entry.
type Writer interface {
	Write(Entry) error
}
