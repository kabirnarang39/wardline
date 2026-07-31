package adapter_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	policyadapter "github.com/kabirnarang39/wardline/internal/features/policy/adapter"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	"github.com/kabirnarang39/wardline/internal/features/policygen/adapter"
)

func testMeta() adapter.Meta {
	return adapter.Meta{
		From:         time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC),
		To:           time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
		EntryCount:   1203,
		SkippedLines: 0,
	}
}

func TestWriteFile_GeneratedFileLoadsThroughTheRealPolicyLoader(t *testing.T) {
	rules := []policydomain.Rule{
		{Identity: "alice", Tool: "read_file", Effect: policydomain.EffectAllow},
		{Identity: "alice", Tool: "write_file", Tenant: "acme", Effect: policydomain.EffectAllow},
	}
	path := filepath.Join(t.TempDir(), "policy.generated.yaml")
	if err := adapter.WriteFile(path, rules, testMeta()); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	matcher, err := policyadapter.LoadFile(path)
	if err != nil {
		t.Fatalf("policy/adapter.LoadFile rejected the generated file: %v", err)
	}
	if got := matcher.Evaluate(policydomain.Context{Identity: "alice", Tool: "read_file"}).Effect; got != policydomain.EffectAllow {
		t.Errorf("expected alice/read_file to be allowed, got %q", got)
	}
	if got := matcher.Evaluate(policydomain.Context{Identity: "alice", Tool: "write_file", Tenant: "acme"}).Effect; got != policydomain.EffectAllow {
		t.Errorf("expected alice/write_file in tenant acme to be allowed, got %q", got)
	}
	if got := matcher.Evaluate(policydomain.Context{Identity: "alice", Tool: "write_file", Tenant: "widgets-inc"}).Effect; got != policydomain.EffectDeny {
		t.Errorf("expected alice/write_file in a DIFFERENT tenant to fall through to default deny, got %q", got)
	}
	if got := matcher.Evaluate(policydomain.Context{Identity: "mallory", Tool: "read_file"}).Effect; got != policydomain.EffectDeny {
		t.Errorf("expected an unlisted identity to fall through to default deny, got %q", got)
	}
}

func TestWriteFile_EmptyRulesStillWritesValidAllDenyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.generated.yaml")
	if err := adapter.WriteFile(path, nil, testMeta()); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !containsLine(string(data), "rules: []") {
		t.Errorf("expected an explicit \"rules: []\" line in the empty-rules output, got:\n%s", data)
	}
	matcher, err := policyadapter.LoadFile(path)
	if err != nil {
		t.Fatalf("policy/adapter.LoadFile rejected the empty-rules file: %v", err)
	}
	if got := matcher.Evaluate(policydomain.Context{Identity: "anyone", Tool: "anything"}).Effect; got != policydomain.EffectDeny {
		t.Errorf("expected an empty-rules file to deny everything, got %q", got)
	}
}

func TestWriteFile_OutputIsDeterministicAcrossRuns(t *testing.T) {
	rules := []policydomain.Rule{
		{Identity: "alice", Tool: "read_file", Effect: policydomain.EffectAllow},
		{Identity: "bob", Tool: "write_file", Tenant: "acme", Effect: policydomain.EffectAllow},
	}
	path1 := filepath.Join(t.TempDir(), "a.yaml")
	path2 := filepath.Join(t.TempDir(), "b.yaml")
	if err := adapter.WriteFile(path1, rules, testMeta()); err != nil {
		t.Fatalf("WriteFile (1): %v", err)
	}
	if err := adapter.WriteFile(path2, rules, testMeta()); err != nil {
		t.Fatalf("WriteFile (2): %v", err)
	}
	data1, _ := os.ReadFile(path1)
	data2, _ := os.ReadFile(path2)
	if string(data1) != string(data2) {
		t.Errorf("expected byte-identical output for identical input, got:\n---1---\n%s\n---2---\n%s", data1, data2)
	}
}

func TestWriteFile_RefusesToOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.generated.yaml")
	if err := os.WriteFile(path, []byte("already here\n"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	err := adapter.WriteFile(path, nil, testMeta())
	if err == nil {
		t.Fatal("expected WriteFile to refuse an existing path, got nil error")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "already here\n" {
		t.Errorf("expected the existing file to be left untouched, got:\n%s", data)
	}
}

func containsLine(text, line string) bool {
	for _, l := range splitLines(text) {
		if l == line {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	return lines
}
