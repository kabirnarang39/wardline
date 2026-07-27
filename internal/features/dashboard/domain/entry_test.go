package domain_test

import (
	"testing"
	"time"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
)

func TestFromAuditEntry(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ae := auditdomain.Entry{
		Timestamp: ts,
		Identity:  "agent-1",
		Tool:      "read_file",
		Decision:  "deny",
		LatencyMS: 12,
		Reason:    "no matching rule",
		TraceID:   "trace-xyz",
	}

	got := domain.FromAuditEntry(42, ae)

	want := domain.LiveEntry{
		ID:        42,
		Timestamp: ts,
		Identity:  "agent-1",
		Tool:      "read_file",
		Decision:  "deny",
		LatencyMS: 12,
		Reason:    "no matching rule",
		TraceID:   "trace-xyz",
	}
	if got != want {
		t.Errorf("FromAuditEntry() = %+v, want %+v", got, want)
	}
}
