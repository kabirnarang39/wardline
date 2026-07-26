package adapter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFile_Valid(t *testing.T) {
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
  - identity: "agent-abc123"
    tool: "*"
    effect: deny
default: deny
`)
	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Evaluate("agent-abc123", "read_file")
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q", got.Effect)
	}
	got = m.Evaluate("agent-abc123", "delete_file")
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny, got %q", got.Effect)
	}
}

func TestLoadFile_InvalidEffect(t *testing.T) {
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: maybe
default: deny
`)
	_, err := adapter.LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid effect, got nil")
	}
}

func TestLoadFile_InvalidDefault(t *testing.T) {
	path := writeTemp(t, `
rules: []
default: sometimes
`)
	_, err := adapter.LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid default, got nil")
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	_, err := adapter.LoadFile("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadFile_UnknownTopLevelKey(t *testing.T) {
	path := writeTemp(t, `
rulez:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: allow
`)
	_, err := adapter.LoadFile(path)
	if err == nil {
		t.Fatal("expected error for unknown top-level key (typo'd 'rulez'), got nil")
	}
}
