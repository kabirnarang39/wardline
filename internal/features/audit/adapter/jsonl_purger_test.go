package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
)

func writeAuditJSONLFile(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJSONLPurger_RemovesEntriesOlderThanCutoff(t *testing.T) {
	path := writeAuditJSONLFile(t, []string{
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"old","tool":"read_file","decision":"allow","latency_ms":1}`,
		`{"timestamp":"2026-01-10T00:00:00Z","identity":"at-cutoff","tool":"read_file","decision":"allow","latency_ms":2}`,
		`{"timestamp":"2026-01-20T00:00:00Z","identity":"recent","tool":"read_file","decision":"allow","latency_ms":3}`,
	})
	p := adapter.NewJSONLPurger(path)
	cutoff := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	deleted, err := p.Purge(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted entry, got %d", deleted)
	}

	remaining, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(remaining)
	if strings.Contains(got, `"identity":"old"`) {
		t.Error("expected the old entry to be removed")
	}
	if !strings.Contains(got, `"identity":"at-cutoff"`) || !strings.Contains(got, `"identity":"recent"`) {
		t.Errorf("expected at-cutoff and recent entries to survive, got:\n%s", got)
	}
}

func TestJSONLPurger_NeverDropsAnUnparsableLine(t *testing.T) {
	path := writeAuditJSONLFile(t, []string{
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"old","tool":"read_file","decision":"allow","latency_ms":1}`,
		`not valid json at all`,
		`{"timestamp":"2026-01-20T00:00:00Z","identity":"recent","tool":"read_file","decision":"allow","latency_ms":3}`,
	})
	p := adapter.NewJSONLPurger(path)
	cutoff := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // after everything

	deleted, err := p.Purge(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	// Only the two parsable, genuinely-old entries count as deleted --
	// the unparsable line is always kept, never counted as purged.
	if deleted != 2 {
		t.Fatalf("expected 2 deleted (parsable) entries, got %d", deleted)
	}

	remaining, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(remaining), "not valid json at all") {
		t.Errorf("expected the unparsable line to survive the purge, got:\n%s", remaining)
	}
}

func TestJSONLPurger_NoEntriesOlderThanCutoff_FileUnchanged(t *testing.T) {
	path := writeAuditJSONLFile(t, []string{
		`{"timestamp":"2026-01-20T00:00:00Z","identity":"recent","tool":"read_file","decision":"allow","latency_ms":3}`,
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	p := adapter.NewJSONLPurger(path)
	deleted, err := p.Purge(context.Background(), time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted entries, got %d", deleted)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("expected the file to be untouched when nothing needs purging")
	}
}

func TestJSONLPurger_MissingFile(t *testing.T) {
	p := adapter.NewJSONLPurger("/nonexistent/audit.jsonl")
	_, err := p.Purge(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
