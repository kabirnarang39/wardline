package main_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTempIdentitiesFile writes body to a fresh identities.yaml under
// t.TempDir() and returns its path -- the same inline pattern
// e2e_tenant_isolation_test.go uses for credentials.yaml, extracted here
// since both new tests below need one.
func writeTempIdentitiesFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "identities.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// This file replays, against the real compiled Wardline binary, the failure
// chain from the July 2026 OpenAI/Hugging Face incident (disclosed at Black
// Hat 2026): a sandboxed evaluation agent found a live network path out of
// its intended boundary, obtained credentials that outlived the single task
// they were issued for, and used them to move laterally into production
// systems it was never scoped to reach, coordinating with a second agent
// over a covert channel the whole time.
//
// Wardline's architecture (one instance wired to one fixed upstream,
// internal/features/proxy/adapter/handler.go's `upstream *url.URL`) doesn't
// have an equivalent of the incident's first stage -- an agent choosing
// among multiple possible egress destinations -- since policy.domain.Context
// carries no destination-host field at all (Identity/Tool/Method/Tenant/
// Params only; see internal/features/policy/domain/policy.go). That stage
// is deliberately NOT reproduced here: faking a scenario Wardline's current
// single-upstream model doesn't have would prove nothing.
//
// What *does* map, stage by stage:
//
//   - The incident's actual named root cause -- a harvested credential that
//     "remained valid and reached beyond any single job" -- is
//     TestServeEndToEnd_IncidentReplay_ExpiredCredentialCannotOutliveItsTask.
//   - Lateral movement across a boundary the credential was never scoped
//     for is TestServeEndToEnd_IncidentReplay_RevokedCredentialCannotReachAnotherIdentity.
//   - The two agents' contradictory signals producing an uninterpretable
//     policy verdict is TestServeEndToEnd_IncidentReplay_AmbiguousMultiAgentSignalFailsClosed.
//   - The malformed/cut-short stream and hung-upstream stages are already
//     proven, not duplicated here: see
//     internal/features/proxy/adapter/handler_transport_test.go's
//     TestReadResponseSignal_SSEResponseNeverBlocksOnBody and
//     handler_timeout_test.go's TestHandler_SlowUpstreamTimesOut.
//
// Known, undemonstrated gap (say so, don't hide it): the incident ran
// undetected for weeks because each individual call looked legitimate in
// isolation. Wardline's audit trail is per-decision, not a volume/pattern
// anomaly signal across time for a single identity's history -- that is not
// exercised here because it does not yet exist.

// TestServeEndToEnd_IncidentReplay_ExpiredCredentialCannotOutliveItsTask is
// the headline scenario: with access_token_ttl_seconds set to 3, a freshly
// bootstrapped token works immediately, then -- once it has outlived the
// single short-lived task it was issued for -- is rejected outright. The
// incident's own post-mortems (CSA, SANS) name exactly this as the fix that
// would have capped the blast radius: a harvested credential is worthless
// once it can no longer reach beyond the job it was minted for.
//
// access_token_ttl_seconds is 3, not 1: JWT exp/iat are integer Unix
// seconds, so a 1-second TTL can leave as little as ~0ms of real validity
// depending on where issuance lands inside its second (issued at x.999s,
// iat truncates to x, exp to x+1 -- expiring almost immediately). That
// raced itself intermittently in CI. 3 seconds keeps a comfortable floor
// even at the worst truncation, while the sleep below (3.5s) still safely
// clears it either way.
func TestServeEndToEnd_IncidentReplay_ExpiredCredentialCannotOutliveItsTask(t *testing.T) {
	credentialsPath := writeTempIdentitiesFile(t, `
identities:
  - name: sandboxed-agent
    secret: "incident-replay-secret-0001"
    tenant: eval-sandbox
`)

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "sandboxed-agent"
    tool: "read_scratch"
    effect: allow
    tenant: "eval-sandbox"
default: deny
`, `features:
  credential_issuance: true
credential:
  identities_file: "`+credentialsPath+`"
  access_token_ttl_seconds: 3
`)

	token := bootstrapToken(t, addr, "incident-replay-secret-0001")

	// The task the credential was actually issued for: allowed, immediately.
	if code := postToolCallWithBearer(t, addr, token, "read_scratch").StatusCode; code != http.StatusOK {
		t.Fatalf("expected 200 for the credential's own task while still fresh, got %d (stderr: %s)", code, stderr.String())
	}

	// Outlive the task: sleep past access_token_ttl_seconds, with headroom
	// for integer-second truncation in either direction.
	time.Sleep(3500 * time.Millisecond)

	// The same token, replayed after outliving its task, must be worthless --
	// this is the exact failure mode named in the incident's post-mortems.
	if code := postToolCallWithBearer(t, addr, token, "read_scratch").StatusCode; code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a credential replayed after outliving its task (the incident's actual root cause), got %d (stderr: %s)", code, stderr.String())
	}
}

// TestServeEndToEnd_IncidentReplay_RevokedCredentialCannotReachAnotherIdentity
// proves containment: revoking one compromised identity's credential must
// not become a system-wide kill switch, and must not let that credential's
// holder reach a tool scoped to a completely different identity. Mirrors the
// blast-radius-containment property TestServeEndToEnd_TenantIsolation_CrossTenantRevoke
// already proves for the tenant dimension; this test frames the identical
// mechanism against the incident's "harvested credential moved laterally"
// stage specifically.
func TestServeEndToEnd_IncidentReplay_RevokedCredentialCannotReachAnotherIdentity(t *testing.T) {
	credentialsPath := writeTempIdentitiesFile(t, `
identities:
  - name: compromised-agent
    secret: "incident-replay-secret-0002"
    tenant: eval-sandbox
  - name: unrelated-agent
    secret: "incident-replay-secret-0003"
    tenant: eval-sandbox
`)

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "compromised-agent"
    tool: "read_scratch"
    effect: allow
    tenant: "eval-sandbox"
  - identity: "unrelated-agent"
    tool: "read_scratch"
    effect: allow
    tenant: "eval-sandbox"
default: deny
`, `features:
  credential_issuance: true
credential:
  identities_file: "`+credentialsPath+`"
`)

	compromisedToken := bootstrapToken(t, addr, "incident-replay-secret-0002")
	unrelatedToken := bootstrapToken(t, addr, "incident-replay-secret-0003")

	// Both work before the compromise is caught.
	if code := postToolCallWithBearer(t, addr, compromisedToken, "read_scratch").StatusCode; code != http.StatusOK {
		t.Fatalf("expected 200 before revoke, got %d (stderr: %s)", code, stderr.String())
	}
	if code := postToolCallWithBearer(t, addr, unrelatedToken, "read_scratch").StatusCode; code != http.StatusOK {
		t.Fatalf("expected 200 for the unrelated identity before any revoke, got %d (stderr: %s)", code, stderr.String())
	}

	revokeResp, err := http.Post("http://"+addr+"/credentials/revoke", "application/json", strings.NewReader(`{"identity":"compromised-agent"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke compromised-agent: want 204, got %d (stderr: %s)", revokeResp.StatusCode, stderr.String())
	}

	// The revoked identity is genuinely denied now.
	if code := postToolCallWithBearer(t, addr, compromisedToken, "read_scratch").StatusCode; code != http.StatusUnauthorized {
		t.Errorf("expected 401 for the revoked (formerly compromised) credential, got %d (stderr: %s)", code, stderr.String())
	}
	// The revoke is scoped to that one identity -- it is not a kill switch:
	// an entirely unrelated agent sharing nothing but the same tool grant
	// must be completely unaffected. This is the actual "blast radius"
	// property the incident's lateral-movement stage broke.
	if code := postToolCallWithBearer(t, addr, unrelatedToken, "read_scratch").StatusCode; code != http.StatusOK {
		t.Errorf("expected 200 for the unrelated identity, unaffected by another identity's revoke, got %d (stderr: %s)", code, stderr.String())
	}
}

// ambiguousMultiAgentPolicy allows a normal, single-agent-originated call
// outright, but a call carrying the conflicting_tool marker -- standing in
// for two agents having fed the system contradictory instructions about the
// same action -- resolves `allow` to a non-boolean value instead of a clean
// true/false. Mirrors policy/adapter/opa/engine_test.go's
// TestOPAEngine_NonBooleanAllow's fixture shape, wired through the real
// binary instead of the engine in isolation.
const ambiguousMultiAgentPolicy = `package wardline.authz

default allow = false

allow {
	input.tool == "safe_tool"
	input.identity == "agent-abc123"
}

allow = "ambiguous" {
	input.tool == "conflicting_tool"
}
`

// TestServeEndToEnd_IncidentReplay_AmbiguousMultiAgentSignalFailsClosed
// proves the property the Reddit thread this replay is answering actually
// asked about: when the policy signal for a call can't be cleanly resolved
// to true or false -- the shape two agents feeding contradictory
// instructions about the same action would produce -- Wardline denies
// rather than guessing. A normal, unambiguous call from the same identity is
// allowed in the same test, so this isn't just "everything is denied."
func TestServeEndToEnd_IncidentReplay_AmbiguousMultiAgentSignalFailsClosed(t *testing.T) {
	addr, _, stderr, _, _ := startWardline(t, "policy.rego", ambiguousMultiAgentPolicy, `policy_backend: opa`)

	if code := postToolCall(t, addr, "agent-abc123", "safe_tool").StatusCode; code != http.StatusOK {
		t.Fatalf("expected 200 for an unambiguous, policy-allowed call, got %d (stderr: %s)", code, stderr.String())
	}

	if code := postToolCall(t, addr, "agent-abc123", "conflicting_tool").StatusCode; code != http.StatusForbidden {
		t.Errorf("expected 403 (fail closed) for a call whose policy signal resolves to a non-boolean value, got %d (stderr: %s)", code, stderr.String())
	}
}
