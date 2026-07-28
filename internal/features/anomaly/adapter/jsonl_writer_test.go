package adapter_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

func TestJSONLWriter_WritesOneJSONObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	w := adapter.NewJSONLWriter(&buf)

	a1 := domain.Anomaly{
		Timestamp: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		Identity:  "alice",
		Kind:      domain.KindNovelTool,
		Detail:    "first call from this identity to tool read_file",
		Entry:     auditdomain.Entry{Identity: "alice", Tool: "read_file", Decision: "allow"},
	}
	a2 := domain.Anomaly{
		Timestamp: time.Date(2026, 7, 28, 12, 1, 0, 0, time.UTC),
		Identity:  "bob",
		Kind:      domain.KindRateSpike,
		Detail:    "call rate exceeded the identity's own trailing baseline",
	}

	if err := w.Write(a1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := w.Write(a2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scanner := bufio.NewScanner(&buf)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if decoded["identity"] != "alice" || decoded["kind"] != "novel_tool" {
		t.Errorf("unexpected decoded line 1: %+v", decoded)
	}
	if decoded["tool"] != "read_file" {
		t.Errorf("expected the triggering entry's tool to be embedded, got %+v", decoded)
	}

	// a2 carries no triggering Entry (rate-spike is volumetric, not
	// tool-scoped), so the omitempty-tagged fields must be absent from the
	// line rather than present-and-empty -- a consumer distinguishes "this
	// anomaly has no tool" from "the tool was the empty string".
	var decoded2 map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &decoded2); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v", err)
	}
	if _, ok := decoded2["tool"]; ok {
		t.Errorf("expected \"tool\" to be omitted for a zero-value Entry, got %+v", decoded2)
	}
	if _, ok := decoded2["decision"]; ok {
		t.Errorf("expected \"decision\" to be omitted for a zero-value Entry, got %+v", decoded2)
	}
}
