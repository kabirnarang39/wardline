package main_test

import (
	"net/http"
	"testing"
)

// taintPolicy allows agent-abc123's tools/call unless the session is tainted;
// a tainted write (any tools/call) is denied. input.tainted is populated only
// when taint_tracking is on.
const taintPolicy = `package wardline.authz

default allow = false

is_write {
	input.method == "tools/call"
}

deny_tainted_write {
	input.tainted
	is_write
}

allow {
	input.identity == "agent-abc123"
	not deny_tainted_write
}
`

// TestServeEndToEnd_TaintGatesWriteAfterUntrustedRead proves the whole taint
// pipeline through the real binary: with taint_tracking on and web_fetch
// configured untrusted, a call to web_fetch taints the identity's session (via
// the live audit stream), so the very next write is denied — while an identity
// that never touched an untrusted source writes freely.
func TestServeEndToEnd_TaintGatesWriteAfterUntrustedRead(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.rego", taintPolicy, `policy_backend: opa
features:
  taint_tracking: true
taint:
  untrusted_sources:
    - web_fetch`)

	// A write with no prior untrusted read is allowed.
	cleanWrite := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if cleanWrite.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for an untainted write, got %d (stderr: %s)", cleanWrite.StatusCode, stderr.String())
	}

	// The untrusted read itself is allowed (taint is set only after it
	// completes), and it taints the session.
	untrustedRead := postToolCall(t, listenAddr, "agent-abc123", "web_fetch")
	if untrustedRead.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the untrusted read, got %d (stderr: %s)", untrustedRead.StatusCode, stderr.String())
	}

	// The next write from the now-tainted session is denied.
	taintedWrite := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if taintedWrite.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a write after an untrusted read, got %d (stderr: %s)", taintedWrite.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_TaintOffHasNoEffect proves taint_tracking is fully gated:
// with the flag off, the identical untrusted-read-then-write sequence writes
// freely — input.tainted is always false, so the policy never denies.
func TestServeEndToEnd_TaintOffHasNoEffect(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.rego", taintPolicy, `policy_backend: opa
taint:
  untrusted_sources:
    - web_fetch`)

	if got := postToolCall(t, listenAddr, "agent-abc123", "web_fetch"); got.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the untrusted read with taint off, got %d (stderr: %s)", got.StatusCode, stderr.String())
	}
	afterRead := postToolCall(t, listenAddr, "agent-abc123", "delete_file")
	if afterRead.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a write after an untrusted read when taint is off, got %d (stderr: %s)", afterRead.StatusCode, stderr.String())
	}
}
