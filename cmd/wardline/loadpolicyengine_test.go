package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPolicyEngine covers the loader-selection boundary that
// runValidatePolicy's raw, unvalidated -backend flag reaches directly (the
// CLI-level test the design spec's Testing section required but which
// was never added in any of the earlier tasks).
func TestLoadPolicyEngine(t *testing.T) {
	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, []byte(`
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`), 0644); err != nil {
		t.Fatal(err)
	}

	regoPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte(`package wardline.authz

default allow = false
`), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		backend string
		path    string
		wantErr bool
	}{
		{"yaml backend loads a yaml file", "yaml", yamlPath, false},
		{"opa backend loads a rego file", "opa", regoPath, false},
		{"empty backend defaults to yaml", "", yamlPath, false},
		{"unknown backend is rejected", "bogus", yamlPath, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadPolicyEngine(tc.backend, tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error for backend %q, got nil", tc.backend)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for backend %q: %v", tc.backend, err)
			}
		})
	}
}
