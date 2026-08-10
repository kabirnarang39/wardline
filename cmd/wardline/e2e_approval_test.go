package main_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// approvalE2EPolicy allows agent-abc123's tools/call, but routes a tainted
// write to the approval workflow: `approval` fires for a tainted write, and
// (since the OPA adapter gives approval precedence over allow) that yields a
// needs_approval outcome. An untainted call — the initial web_fetch read, or a
// write with no prior untrusted source — is allowed outright. Mirrors the
// three-way shape of taintPolicy in e2e_taint_test.go.
const approvalE2EPolicy = `package wardline.authz

default allow = false

is_write {
	input.method == "tools/call"
}

needs {
	input.tainted
	is_write
}

approval {
	needs
}

allow {
	input.identity == "agent-abc123"
	not needs
}
`

// firstPendingID lists the pending approvals over the loopback operator
// surface and returns the first one's id.
func firstPendingID(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/approvals/pending")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /approvals/pending: got %d", resp.StatusCode)
	}
	var pending []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		t.Fatalf("decode pending: %v", err)
	}
	if len(pending) == 0 {
		t.Fatal("expected at least one pending approval, got none")
	}
	return pending[0].ID
}

// TestServeEndToEnd_ApprovalGrantsAfterApprove proves the whole approval
// pipeline through the real binary: with taint_tracking + approval_workflow on
// and web_fetch untrusted, an untrusted read taints the session, the next write
// is held for approval (202), an operator approve mints a single-use grant that
// admits exactly one retry (200), and the write after that is held again (202).
func TestServeEndToEnd_ApprovalGrantsAfterApprove(t *testing.T) {
	addr, _, stderr, _, _ := startWardline(t, "policy.rego", approvalE2EPolicy, `policy_backend: opa
features:
  taint_tracking: true
  approval_workflow: true
taint:
  untrusted_sources:
    - web_fetch`)

	// 1. Untrusted read is allowed and taints the session.
	if got := postToolCall(t, addr, "agent-abc123", "web_fetch"); got.StatusCode != http.StatusOK {
		t.Fatalf("read: got %d (stderr %s)", got.StatusCode, stderr.String())
	}

	// 2. The now-tainted write is held for approval.
	pending := postToolCall(t, addr, "agent-abc123", "delete_file")
	if pending.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 pending, got %d (stderr %s)", pending.StatusCode, stderr.String())
	}

	// 3. List the pending request and approve it over the loopback surface.
	id := firstPendingID(t, addr)
	approveResp, err := http.Post("http://"+addr+"/approvals/"+id+"/approve", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusNoContent {
		t.Fatalf("approve: got %d", approveResp.StatusCode)
	}

	// 4. The grant admits exactly one retry.
	if got := postToolCall(t, addr, "agent-abc123", "delete_file"); got.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after approval, got %d (stderr %s)", got.StatusCode, stderr.String())
	}

	// 5. Single-use consumed — the next write is held again.
	if got := postToolCall(t, addr, "agent-abc123", "delete_file"); got.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 again (single-use), got %d (stderr %s)", got.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_ApprovalOffFailsClosed proves approval_workflow gates the
// admit path: with the flag off (taint still on), a needs_approval outcome has
// no manager to enqueue against, so the tainted write fails closed with 403.
func TestServeEndToEnd_ApprovalOffFailsClosed(t *testing.T) {
	addr, _, stderr, _, _ := startWardline(t, "policy.rego", approvalE2EPolicy, `policy_backend: opa
features:
  taint_tracking: true
taint:
  untrusted_sources:
    - web_fetch`)

	if got := postToolCall(t, addr, "agent-abc123", "web_fetch"); got.StatusCode != http.StatusOK {
		t.Fatalf("read: got %d (stderr %s)", got.StatusCode, stderr.String())
	}
	taintedWrite := postToolCall(t, addr, "agent-abc123", "delete_file")
	if taintedWrite.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 (fail closed) with approval off, got %d (stderr %s)", taintedWrite.StatusCode, stderr.String())
	}
}
