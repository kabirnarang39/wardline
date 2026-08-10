package main_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestServeEndToEnd_CostBudgetCeilingExceeded proves the whole
// job_cost_budget pipeline through the real binary: a per-tool cost of 30
// against a ceiling of 50 admits the first call (30<=50) and rejects the
// second (60>50) with 429 and a distinct cost_budget_exceeded audit
// decision.
func TestServeEndToEnd_CostBudgetCeilingExceeded(t *testing.T) {
	listenAddr, stdout, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "llm_call"
    effect: allow
default: deny
`, `features:
  job_cost_budget: true
job_cost_budget:
  ceiling: 50
  tool_costs:
    llm_call: 30`)

	first := postToolCall(t, listenAddr, "agent-abc123", "llm_call")
	if first.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 within the cost ceiling (30<=50), got %d (stderr: %s)", first.StatusCode, stderr.String())
	}
	second := postToolCall(t, listenAddr, "agent-abc123", "llm_call")
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once the cost ceiling is exceeded (60>50), got %d (stderr: %s)", second.StatusCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"decision":"cost_budget_exceeded"`) {
		t.Errorf("expected a cost_budget_exceeded audit entry, stdout: %s", stdout.String())
	}
}

// TestServeEndToEnd_CostBudgetOffHasNoEffect proves job_cost_budget is fully
// inert when the flag is off — no ceiling wiring means no wired feature at
// all, not a default ceiling silently applying.
func TestServeEndToEnd_CostBudgetOffHasNoEffect(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "agent-abc123"
    tool: "llm_call"
    effect: allow
default: deny
`, "")

	for i := 0; i < 5; i++ {
		resp := postToolCall(t, listenAddr, "agent-abc123", "llm_call")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: expected 200 with job_cost_budget off, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}
}

// TestServeEndToEnd_AllFourFlagsCostBudgetApprovalGrantAdmitsRetry is the
// mandatory regression this plan exists to get right the first time (see
// design spec §D): all four flags together, drive a job over its cost
// ceiling, get 202 pending, approve, retry -> must be 200, not 429.
func TestServeEndToEnd_AllFourFlagsCostBudgetApprovalGrantAdmitsRetry(t *testing.T) {
	policy := `package wardline.authz

default allow = false

is_write { input.method == "tools/call" }

approval {
	input.cost_over_budget
	is_write
}

allow {
	input.identity == "agent-abc123"
}
`
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.rego", policy, `policy_backend: opa
features:
  taint_tracking: true
  approval_workflow: true
  job_cost_budget: true
taint:
  untrusted_sources:
    - web_fetch
job_cost_budget:
  ceiling: 50
  tool_costs:
    llm_call: 60`)

	// The first call's own cost (60) already exceeds the ceiling (50), but
	// cost_over_budget is a peek at PRIOR calls only (never this one -- see
	// costbudget/usecase.Checker.IsOverBudget's doc comment), so this first
	// call is evaluated as within budget by policy, forwarded, and only then
	// hard-gated to 429 by the Check hard gate below -- which still commits
	// its cost (60) to the meter even though it denied the call.
	first := postToolCall(t, listenAddr, "agent-abc123", "llm_call")
	if first.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on the first over-ceiling call (established via the hard gate), got %d (stderr: %s)", first.StatusCode, stderr.String())
	}

	// The second call now sees cost_over_budget=true from the peek (prior
	// total 60 >= ceiling 50) -> routed to approval.
	pending := postToolCall(t, listenAddr, "agent-abc123", "llm_call")
	if pending.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 pending (over cost ceiling), got %d (stderr: %s)", pending.StatusCode, stderr.String())
	}

	id := firstPendingID(t, listenAddr)
	approveResp, err := http.Post("http://"+listenAddr+"/approvals/"+id+"/approve", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusNoContent {
		t.Fatalf("approve: got %d", approveResp.StatusCode)
	}

	retry := postToolCall(t, listenAddr, "agent-abc123", "llm_call")
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after approval despite the cost ceiling (the grant-override fix), got %d (stderr: %s)", retry.StatusCode, stderr.String())
	}
}
