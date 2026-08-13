package main_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// TestServeEndToEnd_TaintedDenialRecordsSourceInAudit closes a real gap:
// taint/domain.Label has carried Sources since taint tracking shipped, but
// nothing ever read it back out -- an operator investigating a
// tainted-write denial could see THAT a call was tainted (only if the
// policy author's own reason string happened to mention it) but never
// WHICH untrusted call actually caused it, from Wardline's own audit trail.
// Proves, through the real binary, that the denied write's audit entry now
// carries taint_sources regardless of what the policy's reason string says.
func TestServeEndToEnd_TaintedDenialRecordsSourceInAudit(t *testing.T) {
	listenAddr, stdout, stderr, _, _ := startWardline(t, "policy.rego", taintPolicy, `policy_backend: opa
features:
  taint_tracking: true
taint:
  untrusted_sources:
    - web_fetch`)

	if got := postToolCall(t, listenAddr, "agent-abc123", "web_fetch"); got.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the untrusted read, got %d (stderr: %s)", got.StatusCode, stderr.String())
	}
	if got := postToolCall(t, listenAddr, "agent-abc123", "delete_file"); got.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for the tainted write, got %d (stderr: %s)", got.StatusCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"taint_sources":["web_fetch"]`) {
		t.Errorf("expected the tainted write's audit entry to record taint_sources, got stdout:\n%s", stdout.String())
	}
}

// postToolCallWithSession is like postToolCall but adds an explicit
// X-Wardline-Session header, exercising the header-preference branch of
// SessionID on both the taint SET path (audit Entry.SessionID) and the
// decision-time READ path (proxydomain.ToolCall.SessionID) -- see
// TestServeEndToEnd_TaintHonorsSessionHeader.
func postToolCallWithSession(t *testing.T, listenAddr, identity, tool, session string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":%q}}`, tool)
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Wardline-Identity", identity)
	req.Header.Set("X-Wardline-Session", session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	return resp
}

// TestServeEndToEnd_TaintHonorsSessionHeader is the regression test for the
// decision-time taint lookup ignoring the X-Wardline-Session header (it
// hardcoded "" and always fell back to the TTL-window bucket, diverging
// from Publish's set-side header preference). Proves, through the real
// wiring in cmd/wardline: an untrusted read tainted under an explicit
// session header gates a write carrying that SAME header, while a write
// carrying a DIFFERENT session header is untainted -- ruling out "session
// ignored entirely, everything taints" as a false-positive explanation.
func TestServeEndToEnd_TaintHonorsSessionHeader(t *testing.T) {
	listenAddr, _, stderr, _, _ := startWardline(t, "policy.rego", taintPolicy, `policy_backend: opa
features:
  taint_tracking: true
taint:
  untrusted_sources:
    - web_fetch`)

	untrustedRead := postToolCallWithSession(t, listenAddr, "agent-abc123", "web_fetch", "run-1")
	if untrustedRead.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the untrusted read, got %d (stderr: %s)", untrustedRead.StatusCode, stderr.String())
	}

	sameSessionWrite := postToolCallWithSession(t, listenAddr, "agent-abc123", "delete_file", "run-1")
	if sameSessionWrite.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a write on the same session header as the untrusted read, got %d (stderr: %s)", sameSessionWrite.StatusCode, stderr.String())
	}

	differentSessionWrite := postToolCallWithSession(t, listenAddr, "agent-abc123", "delete_file", "run-2")
	if differentSessionWrite.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a write on a different session header (isolation), got %d (stderr: %s)", differentSessionWrite.StatusCode, stderr.String())
	}
}
