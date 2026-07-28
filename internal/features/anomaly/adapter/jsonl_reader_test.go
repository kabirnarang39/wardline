package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
)

func writeAnomalyJSONLFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "anomaly.jsonl")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJSONLReader_QueryReturnsAnomaliesInRange(t *testing.T) {
	path := writeAnomalyJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"alice","kind":"novel_tool","detail":"first call","tool":"read_file"}`,
		`{"timestamp":"2026-01-02T00:00:00Z","identity":"bob","kind":"rate_spike","detail":"spike","tool":"read_file","decision":"allow"}`,
	)
	r := adapter.NewJSONLReader(path)

	got, err := r.Query(context.Background(),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Identity != "bob" {
		t.Fatalf("expected only bob's anomaly, got %+v", got)
	}
	if got[0].Entry.Tool != "read_file" || got[0].Entry.Decision != "allow" {
		t.Errorf("expected the triggering entry's tool/decision to round-trip, got %+v", got[0].Entry)
	}
}

func TestJSONLReader_AnomalyMalformedLineIsSkippedAndCounted(t *testing.T) {
	path := writeAnomalyJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"alice","kind":"novel_tool","detail":"first call","tool":"read_file"}`,
		`not valid json`,
	)
	r := adapter.NewJSONLReader(path)

	got, err := r.Query(context.Background(), time.Time{}, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 valid anomaly, got %d", len(got))
	}
	if r.SkippedLines != 1 {
		t.Errorf("expected SkippedLines == 1, got %d", r.SkippedLines)
	}
}

func TestJSONLReader_AnomalyMissingFileErrors(t *testing.T) {
	r := adapter.NewJSONLReader(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	_, err := r.Query(context.Background(), time.Time{}, time.Now())
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
