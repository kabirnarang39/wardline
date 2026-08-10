package main_test

import (
	"net/http"
	"testing"
)

// jobBudgetApprovalPolicy mirrors the exact example from
// docs-site/content/features/job-budget.md: pairing input.job_over_budget
// with approval routes an over-budget job through the approval workflow
// instead of a flat 429.
const jobBudgetApprovalPolicy = `package wardline.authz

default allow = false

approval {
	input.job_over_budget
}

allow {
	input.identity == "agent-abc123"
}
`

// TestServeEndToEnd_AllThreeFlagsJobBudgetApprovalGrantAdmitsRetry proves
// taint_tracking, approval_workflow, and job_budget all wired together
// through the real binary: a job driven to its requests_per_job ceiling
// routes its next call to needs_approval (202) rather than a flat 429,
// operator approval mints a single-use grant, and retrying the SAME
// over-budget call is forwarded (200) instead of hitting the job-budget hard
// gate's 429 -- the fix for finding C1, exercised end to end.
func TestServeEndToEnd_AllThreeFlagsJobBudgetApprovalGrantAdmitsRetry(t *testing.T) {
	addr, _, stderr, _, _ := startWardline(t, "policy.rego", jobBudgetApprovalPolicy, `policy_backend: opa
features:
  taint_tracking: true
  approval_workflow: true
  job_budget: true
taint:
  untrusted_sources:
    - web_fetch
job_budget:
  requests_per_job: 2`)

	// 1-2. Drive the job to its ceiling via ordinary allowed calls.
	for i := 0; i < 2; i++ {
		resp := postToolCall(t, addr, "agent-abc123", "read_file")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: expected 200 within the job ceiling, got %d (stderr: %s)", i+1, resp.StatusCode, stderr.String())
		}
	}

	// 3. The next call over budget is routed to needs_approval, not a flat
	// 429 -- job_over_budget paired with approval in the policy above.
	pending := postToolCall(t, addr, "agent-abc123", "read_file")
	if pending.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 pending once the job ceiling is exceeded, got %d (stderr: %s)", pending.StatusCode, stderr.String())
	}

	// 4. Approve it via the operator surface.
	id := firstPendingID(t, addr)
	approveResp, err := http.Post("http://"+addr+"/approvals/"+id+"/approve", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusNoContent {
		t.Fatalf("approve: got %d", approveResp.StatusCode)
	}

	// 5. Retry the SAME call: the grant must admit it despite the job-budget
	// checker still reporting the ceiling exceeded (nothing decrements it) --
	// the consumed grant must override the hard gate, not lose to it.
	retry := postToolCall(t, addr, "agent-abc123", "read_file")
	if retry.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on the grant-admitted retry, got %d (stderr: %s)", retry.StatusCode, stderr.String())
	}
}
