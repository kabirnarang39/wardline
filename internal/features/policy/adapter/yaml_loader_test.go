package adapter_test

import (
	"os"
	"path/filepath"
	"strings"
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
	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow, got %q", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "delete_file"})
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

func TestLoadFile_ReportsAllProblemsAtOnce(t *testing.T) {
	// Three independent defects in one file: rule 0 has no tool, rule 1 has
	// no identity, and default is an invalid effect. LoadFile must report
	// all three, not just the first one it hits.
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    tool: ""
    effect: allow
  - identity: ""
    tool: "read_file"
    effect: deny
default: sometimes
`)
	_, err := adapter.LoadFile(path)
	if err == nil {
		t.Fatal("expected error for multiple problems, got nil")
	}
	msg := err.Error()
	for _, want := range []string{
		"rule 0: tool must not be empty",
		"rule 1: identity must not be empty",
		"default:",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected error to mention %q, got: %s", want, msg)
		}
	}
}

func TestLoadFile_EmptyRulesValidDefault(t *testing.T) {
	path := writeTemp(t, `
rules: []
default: allow
`)
	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "anyone", Tool: "anything"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected default allow with no rules, got %q", got.Effect)
	}
}

func TestLoadFile_TenantScopedRule(t *testing.T) {
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
    tenant: "acme"
default: deny
`)
	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Tenant: "acme"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow for matching tenant, got %q", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Tenant: "widgets-inc"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected deny for non-matching tenant, got %q", got.Effect)
	}
}

func TestLoadFile_ResourcesReadMethodRule(t *testing.T) {
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    method: "resources/read"
    tool: "file:///data/report.csv"
    effect: allow
default: deny
`)
	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "file:///data/report.csv", Method: "resources/read"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow for matching resources/read rule, got %q", got.Effect)
	}
	got = m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "file:///data/report.csv", Method: "tools/call"})
	if got.Effect != domain.EffectDeny {
		t.Errorf("expected default deny -- same target via tools/call must not match a resources/read-scoped rule, got %q", got.Effect)
	}
}

func TestLoadFile_OmittedMethodDefaultsToToolsCall(t *testing.T) {
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`)
	m, err := adapter.LoadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Evaluate(domain.Context{Identity: "agent-abc123", Tool: "read_file", Method: "tools/call"})
	if got.Effect != domain.EffectAllow {
		t.Errorf("expected allow -- omitted method must default to tools/call, got %q", got.Effect)
	}
}

func TestLoadFile_InvalidMethodRejected(t *testing.T) {
	path := writeTemp(t, `
rules:
  - identity: "agent-abc123"
    method: "bogus"
    tool: "read_file"
    effect: allow
default: deny
`)
	_, err := adapter.LoadFile(path)
	if err == nil {
		t.Fatal("expected error for a method that could never match a real gated request, got nil")
	}
	if !strings.Contains(err.Error(), "method") {
		t.Errorf("expected error to mention the invalid method, got: %v", err)
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
