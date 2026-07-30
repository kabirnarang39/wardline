package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func writeJSONLFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJSONLReader_QueryReturnsEntriesInRange(t *testing.T) {
	path := writeJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"alice","tool":"read_file","decision":"allow","latency_ms":5}`,
		`{"timestamp":"2026-01-02T00:00:00Z","identity":"bob","tool":"read_file","decision":"deny","latency_ms":3}`,
		`{"timestamp":"2026-01-03T00:00:00Z","identity":"carol","tool":"read_file","decision":"allow","latency_ms":7}`,
	)
	r := adapter.NewJSONLReader(path)

	entries, err := r.Query(context.Background(),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].Identity != "bob" {
		t.Fatalf("expected only bob's entry (range boundary: from-inclusive, to-exclusive), got %+v", entries)
	}
}

func TestJSONLReader_FromIsInclusiveToIsExclusive(t *testing.T) {
	path := writeJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"at-from","tool":"read_file","decision":"allow","latency_ms":1}`,
		`{"timestamp":"2026-01-02T00:00:00Z","identity":"at-to","tool":"read_file","decision":"allow","latency_ms":1}`,
	)
	r := adapter.NewJSONLReader(path)

	entries, err := r.Query(context.Background(),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].Identity != "at-from" {
		t.Fatalf("expected only the at-from entry, got %+v", entries)
	}
}

func TestJSONLReader_MalformedLineIsSkippedAndCounted(t *testing.T) {
	path := writeJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"alice","tool":"read_file","decision":"allow","latency_ms":5}`,
		`not valid json`,
		`{"timestamp":"2026-01-01T01:00:00Z","identity":"bob","tool":"read_file","decision":"allow","latency_ms":5}`,
	)
	r := adapter.NewJSONLReader(path)

	entries, err := r.Query(context.Background(),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries around the malformed line, got %d", len(entries))
	}
	if r.SkippedLines != 1 {
		t.Errorf("expected SkippedLines == 1, got %d", r.SkippedLines)
	}
}

func TestJSONLReader_EmptyFileReturnsNoEntriesNoError(t *testing.T) {
	path := writeJSONLFile(t)
	r := adapter.NewJSONLReader(path)

	entries, err := r.Query(context.Background(), time.Time{}, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no entries from an empty file, got %+v", entries)
	}
}

func TestJSONLReader_MissingTenantDefaultsOnRead(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.jsonl"
	// A line predating this cycle -- no "tenant" key at all.
	line := `{"timestamp":"2026-01-01T00:00:00Z","identity":"alice","tool":"search","decision":"allow","latency_ms":5,"reason":"","trace_id":""}`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := adapter.NewJSONLReader(path)
	entries, err := r.Query(context.Background(), time.Time{}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Tenant != tenant.Default {
		t.Fatalf("got %+v, want one entry with Tenant=%q", entries, tenant.Default)
	}
}

func TestJSONLReader_MissingFileErrors(t *testing.T) {
	r := adapter.NewJSONLReader(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	_, err := r.Query(context.Background(), time.Time{}, time.Now())
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
