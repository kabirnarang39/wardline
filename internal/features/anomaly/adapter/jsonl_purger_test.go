package adapter_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
)

func TestJSONLPurger_RemovesEntriesOlderThanCutoff(t *testing.T) {
	path := writeAnomalyJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"old","kind":"novel_tool","detail":"first call"}`,
		`{"timestamp":"2026-01-10T00:00:00Z","identity":"at-cutoff","kind":"novel_tool","detail":"first call"}`,
		`{"timestamp":"2026-01-20T00:00:00Z","identity":"recent","kind":"novel_tool","detail":"first call"}`,
	)
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
	path := writeAnomalyJSONLFile(t,
		`{"timestamp":"2026-01-01T00:00:00Z","identity":"old","kind":"novel_tool","detail":"first call"}`,
		`not valid json at all`,
	)
	p := adapter.NewJSONLPurger(path)
	deleted, err := p.Purge(context.Background(), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted (parsable) entry, got %d", deleted)
	}
	remaining, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(remaining), "not valid json at all") {
		t.Errorf("expected the unparsable line to survive the purge, got:\n%s", remaining)
	}
}

func TestJSONLPurger_MissingFile(t *testing.T) {
	p := adapter.NewJSONLPurger("/nonexistent/anomaly.jsonl")
	_, err := p.Purge(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
