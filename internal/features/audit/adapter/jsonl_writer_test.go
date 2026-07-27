package adapter_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

func TestJSONLWriter_WritesOneLinePerEntry(t *testing.T) {
	var buf bytes.Buffer
	w := adapter.NewJSONLWriter(&buf)

	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := w.Write(domain.Entry{
		Timestamp: ts,
		Identity:  "agent-abc123",
		Tool:      "read_file",
		Decision:  "allow",
		LatencyMS: 7,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := `{"timestamp":"2026-01-01T12:00:00Z","identity":"agent-abc123","tool":"read_file","decision":"allow","latency_ms":7}` + "\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestJSONLWriter_IncludesReasonWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	w := adapter.NewJSONLWriter(&buf)

	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := w.Write(domain.Entry{
		Timestamp: ts,
		Identity:  "agent-abc123",
		Tool:      "read_file",
		Decision:  "deny",
		LatencyMS: 7,
		Reason:    "policy evaluation failed: some internal detail",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := `{"timestamp":"2026-01-01T12:00:00Z","identity":"agent-abc123","tool":"read_file","decision":"deny","latency_ms":7,"reason":"policy evaluation failed: some internal detail"}` + "\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestJSONLWriter_OmitsReasonWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	w := adapter.NewJSONLWriter(&buf)

	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := w.Write(domain.Entry{
		Timestamp: ts,
		Identity:  "agent-abc123",
		Tool:      "read_file",
		Decision:  "allow",
		LatencyMS: 7,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bytes.Contains(buf.Bytes(), []byte("reason")) {
		t.Errorf("expected no reason key when Reason is empty, got: %s", buf.String())
	}
}

func TestJSONLWriter_MultipleWritesAppendLines(t *testing.T) {
	var buf bytes.Buffer
	w := adapter.NewJSONLWriter(&buf)

	entry := domain.Entry{Timestamp: time.Unix(0, 0).UTC(), Identity: "a", Tool: "t", Decision: "deny", LatencyMS: 1}
	_ = w.Write(entry)
	_ = w.Write(entry)

	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	if lines != 2 {
		t.Errorf("expected 2 lines, got %d", lines)
	}
}

func TestJSONLWriter_IncludesTraceIDWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	w := adapter.NewJSONLWriter(&buf)

	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := w.Write(domain.Entry{
		Timestamp: ts,
		Identity:  "agent-abc123",
		Tool:      "read_file",
		Decision:  "allow",
		LatencyMS: 7,
		TraceID:   "4bf92f3577b34da6a3ce929d0e0e4736",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := `{"timestamp":"2026-01-01T12:00:00Z","identity":"agent-abc123","tool":"read_file","decision":"allow","latency_ms":7,"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"}` + "\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}
