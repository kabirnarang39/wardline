package main_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestServeEndToEnd_JobBudgetCeilingExceeded proves the whole job_budget
// pipeline through the real binary: with a requests_per_job ceiling of 2,
// the third call in the same session is rejected with 429 and a distinct
// job_budget_exceeded audit decision, distinguishing it from the per-window
// "throttled" budget mechanism.
func TestServeEndToEnd_JobBudgetCeilingExceeded(t *testing.T) {
	listenAddr, stdout, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, `features:
  job_budget: true
job_budget:
  requests_per_job: 2`)

	for i := 0; i < 2; i++ {
		resp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: expected 200 within the job ceiling, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}
	over := postToolCall(t, listenAddr, "agent-abc123", "read_file")
	if over.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once the job ceiling is exceeded, got %d (stderr: %s)", over.StatusCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"decision":"job_budget_exceeded"`) {
		t.Errorf("expected a job_budget_exceeded audit entry, stdout: %s", stdout.String())
	}
}

// TestServeEndToEnd_JobBudgetOffHasNoEffect proves job_budget is fully inert
// when the flag is off — no ceiling wiring means no wired feature at all,
// not a default-500 ceiling silently applying.
func TestServeEndToEnd_JobBudgetOffHasNoEffect(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "read_file"
    effect: allow
default: deny
`, "")

	for i := 0; i < 5; i++ {
		resp := postToolCall(t, listenAddr, "agent-abc123", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: expected 200 with job_budget off, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}
}
