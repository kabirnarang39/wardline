package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunInferPolicy_EndToEndAgainstAJSONLAuditFile builds the real
// wardline binary and runs `infer-policy` against it, the same
// black-box style e2e_test.go already uses for export-evidence (e.g.
// TestExportEvidenceEndToEnd_RealBundleFromRealBinary) -- this exercises
// the full CLI path (flag parsing, config load, newAuditReader, Infer,
// WriteFile) together, not just the unit-tested pieces.
//
// e2e_test.go has no shared "build once" helper to reuse -- every e2e
// test there (including TestExportEvidenceEndToEnd_StdoutAuditOutputFailsLoud's
// "not queryable" assertion) inlines its own `go build -o binPath .`
// against a per-test t.TempDir() binary path, so this test follows that
// same existing convention rather than introducing a new helper.
func TestRunInferPolicy_EndToEndAgainstAJSONLAuditFile(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "wardline")

	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLines := strings.Join([]string{
		`{"timestamp":"2026-07-25T10:00:00Z","identity":"alice","tenant":"acme","tool":"read_file","decision":"allow"}`,
		`{"timestamp":"2026-07-25T10:00:01Z","identity":"alice","tenant":"acme","tool":"read_file","decision":"allow"}`,
		`{"timestamp":"2026-07-25T10:00:02Z","identity":"alice","tenant":"acme","tool":"delete_file","decision":"deny"}`,
		`{"timestamp":"2026-07-25T10:00:03Z","identity":"bob","tenant":"widgets-inc","tool":"write_file","decision":"passthrough"}`,
		`{"timestamp":"2026-07-25T10:00:04Z","identity":"bob","tenant":"widgets-inc","tool":"write_file","decision":"throttled"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(auditPath, []byte(auditLines), 0600); err != nil {
		t.Fatalf("write audit fixture: %v", err)
	}

	configPath := filepath.Join(dir, "wardline.yaml")
	configYAML := `listen: ":0"
upstream: "http://127.0.0.1:1"
policy_file: "` + filepath.Join(dir, "policy.yaml") + `"
audit:
  output: "` + auditPath + `"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	outputPath := filepath.Join(dir, "policy.generated.yaml")
	cmd := exec.Command(binPath, "infer-policy",
		"-config", configPath,
		"-from", "2026-07-01T00:00:00Z",
		"-to", "2026-08-01T00:00:00Z",
		"-output", outputPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("infer-policy failed: %v\noutput: %s", err, out)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated policy: %v", err)
	}
	got := string(data)

	for _, want := range []string{
		"rules:",
		"identity: alice",
		"tool: read_file",
		"tenant: acme",
		"identity: bob",
		"tool: write_file",
		"tenant: widgets-inc",
		"default: deny",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected generated policy to contain %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "delete_file") {
		t.Errorf("expected the denied delete_file call to be excluded, got:\n%s", got)
	}
	if strings.Contains(got, "throttled") {
		t.Errorf("expected the throttled write_file call to be excluded (only its earlier passthrough should appear), got:\n%s", got)
	}
}
