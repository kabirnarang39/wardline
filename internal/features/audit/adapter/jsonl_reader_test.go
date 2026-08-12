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

// TestJSONLReader_SubSecondBoundaryDoesNotDropEntry is the real-bug
// regression: every stored line's timestamp round-trips at whole-second
// precision (JSONLWriter's own format has no fractional-second
// directive), but a real caller's `from` is an ordinary full-precision
// time.Time -- the scheduled-export job's own window boundaries are
// literal time.Now() calls, so on every tick `from` almost always has a
// non-zero sub-second component. An entry timestamped in that exact
// wall-clock second, before Query started truncating both boundaries,
// compared as "before from" and was silently dropped -- reproduced live
// against a real running wardline instance with compliance_scheduled_export
// on before this fix landed.
func TestJSONLReader_SubSecondBoundaryDoesNotDropEntry(t *testing.T) {
	path := writeJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:05Z","identity":"same-second","tool":"read_file","decision":"allow","latency_ms":1}`,
	)
	r := adapter.NewJSONLReader(path)

	// from's sub-second component (.668) is later within the same wall
	// clock second than the stored entry's truncated 00:00:05.000 --
	// without truncating from down to the second first, ts.Before(from)
	// is true and the entry is wrongly excluded.
	from := time.Date(2026, 1, 1, 0, 0, 5, 668_000_000, time.UTC)
	to := time.Date(2026, 1, 1, 0, 0, 8, 0, time.UTC)

	entries, err := r.Query(context.Background(), from, to)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 || entries[0].Identity != "same-second" {
		t.Fatalf("expected the entry sharing from's wall-clock second to be included, got %+v", entries)
	}
}

func TestJSONLReader_MissingFileErrors(t *testing.T) {
	r := adapter.NewJSONLReader(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	_, err := r.Query(context.Background(), time.Time{}, time.Now())
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
