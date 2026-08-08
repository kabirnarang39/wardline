package adapter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

func TestWriteFile_ValidRules_WritesLoadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	rules := []domain.Rule{
		{Identity: "agent-abc123", Tool: "read_file", Effect: domain.EffectAllow},
		{Identity: "agent-abc123", Tool: "*", Effect: domain.EffectDeny},
	}
	if err := adapter.WriteFile(path, rules, domain.EffectDeny); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("expected the written file to reload cleanly, got: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q", got.Effect)
	}
}

func TestWriteFile_OverwritesExistingFile(t *testing.T) {
	// Unlike policygen/adapter.WriteFile (O_EXCL, refuses to touch an
	// existing file), this IS the dashboard editor's save path --
	// overwriting the operator's own already-live policy file is the
	// whole point.
	path := writeTemp(t, "rules: []\ndefault: allow\n")
	rules := []domain.Rule{{Identity: "alice", Tool: "search", Effect: domain.EffectDeny}}
	if err := adapter.WriteFile(path, rules, domain.EffectDeny); err != nil {
		t.Fatalf("unexpected error overwriting existing file: %v", err)
	}
	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "alice", Tool: "search"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected the overwritten content (deny), got %q -- file wasn't really replaced", got.Effect)
	}
}

func TestWriteFile_InvalidRule_NeverTouchesDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := "rules: []\ndefault: allow\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// Empty Identity is invalid (see ParseYAML's own "identity must not
	// be empty" check) -- WriteFile must reject this BEFORE writing
	// anything, so a bad structured edit can never leave a policy file
	// on disk that wouldn't itself pass a reload.
	badRules := []domain.Rule{{Identity: "", Tool: "search", Effect: domain.EffectAllow}}
	err := adapter.WriteFile(path, badRules, domain.EffectDeny)
	if err == nil {
		t.Fatal("expected an error for an empty identity, got nil")
	}
	if !strings.Contains(err.Error(), "identity must not be empty") {
		t.Errorf("expected the error to explain why, got: %v", err)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != original {
		t.Errorf("expected the original file to survive a rejected write untouched, got:\n%s", got)
	}

	// No stray temp file left behind either.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly the one original file in %s, got %d entries: %+v", dir, len(entries), entries)
	}
}

func TestWriteFile_MethodScopedRule_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	rules := []domain.Rule{
		{Identity: "agent-abc123", Tool: "file:///data/report.csv", Effect: domain.EffectAllow, Method: "resources/read"},
		{Identity: "agent-abc123", Tool: "read_file", Effect: domain.EffectAllow},
	}
	if err := adapter.WriteFile(path, rules, domain.EffectDeny); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("expected the written file to reload cleanly, got: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "file:///data/report.csv", Method: "resources/read"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow for the round-tripped resources/read rule, got %q", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Method: "tools/call"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow for the round-tripped tools/call rule (empty Method), got %q", got.Effect)
	}
}

func TestWriteFile_InvalidDefault_NeverTouchesDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	original := "rules: []\ndefault: allow\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	err := adapter.WriteFile(path, nil, domain.Effect("throttle"))
	if err == nil {
		t.Fatal("expected an error for an invalid default effect, got nil")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != original {
		t.Errorf("expected the original file to survive a rejected write untouched, got:\n%s", got)
	}
}
