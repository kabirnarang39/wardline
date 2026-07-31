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
		// Two allow entries for one triple: exactly one rule, deduped.
		`{"timestamp":"2026-07-25T10:00:00Z","identity":"alice","tenant":"acme","tool":"read_file","decision":"allow"}`,
		`{"timestamp":"2026-07-25T10:00:01Z","identity":"alice","tenant":"acme","tool":"read_file","decision":"allow"}`,
		// Non-allow decisions: never allow-listed.
		`{"timestamp":"2026-07-25T10:00:02Z","identity":"alice","tenant":"acme","tool":"delete_file","decision":"deny"}`,
		`{"timestamp":"2026-07-25T10:00:04Z","identity":"bob","tenant":"widgets-inc","tool":"throttled_file","decision":"throttled"}`,
		// Critical 1: a passthrough entry's tool is a raw JSON-RPC method
		// name policy never evaluated -- excluded even though it looks like
		// a legitimate tool and even though it reached upstream.
		`{"timestamp":"2026-07-25T10:00:03Z","identity":"bob","tenant":"widgets-inc","tool":"write_file","decision":"passthrough"}`,
		// Critical 1 (defense in depth): an allow entry can still never
		// synthesize a wildcard rule.
		`{"timestamp":"2026-07-25T10:00:05Z","identity":"mallory","tenant":"acme","tool":"*","decision":"allow"}`,
		// Critical 2: an allow entry with no identity would produce a file
		// policy/adapter.LoadFile rejects -- excluded.
		`{"timestamp":"2026-07-25T10:00:06Z","identity":"","tenant":"acme","tool":"list_tools","decision":"allow"}`,
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
		"default: deny",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected generated policy to contain %q, got:\n%s", want, got)
		}
	}
	for _, unwanted := range []struct{ needle, why string }{
		{"delete_file", "the denied delete_file call must be excluded"},
		{"throttled_file", "the throttled call must be excluded"},
		{"write_file", "the passthrough call must be excluded: its tool field is a raw JSON-RPC method name, not a policy-evaluated tool"},
		{"bob", "the passthrough entry's caller-supplied identity must not appear"},
		{`"*"`, "an observed allow must never synthesize a wildcard rule"},
		{"mallory", "the wildcard-tool entry must be excluded entirely"},
		{"list_tools", "the empty-identity entry must be excluded (LoadFile rejects an empty identity)"},
		{`identity: ""`, "no rule may have an empty identity"},
	} {
		if strings.Contains(got, unwanted.needle) {
			t.Errorf("found %q in the generated policy but %s; got:\n%s", unwanted.needle, unwanted.why, got)
		}
	}

	// The plan's global constraint: whatever is generated must load through
	// the real, unmodified policy loader. Running the shipped
	// `validate-policy` command against the output proves it end to end --
	// an empty identity or tool would make this fail.
	validate := exec.Command(binPath, "validate-policy", "-file", outputPath)
	if vout, err := validate.CombinedOutput(); err != nil {
		t.Errorf("generated policy failed to load through validate-policy: %v\noutput: %s\npolicy:\n%s", err, vout, got)
	}

	// Exactly one rule survives (alice/acme/read_file, deduped).
	if n := strings.Count(got, "identity:"); n != 1 {
		t.Errorf("expected exactly 1 generated rule, found %d identity: keys in:\n%s", n, got)
	}

	// A -to past now is clamped, so the header never advertises a range the
	// audit trail could not possibly cover. Reuses the binary built above.
	futurePath := filepath.Join(dir, "policy.future.yaml")
	future := exec.Command(binPath, "infer-policy",
		"-config", configPath,
		"-from", "2026-07-01T00:00:00Z",
		"-to", "3000-01-01T00:00:00Z",
		"-output", futurePath,
	)
	if fout, err := future.CombinedOutput(); err != nil {
		t.Fatalf("infer-policy with a future -to failed: %v\noutput: %s", err, fout)
	}
	futureData, err := os.ReadFile(futurePath)
	if err != nil {
		t.Fatalf("read future-range policy: %v", err)
	}
	if strings.Contains(string(futureData), "3000-") {
		t.Errorf("expected a future -to to be clamped to now in the header, got:\n%s", futureData)
	}
}
