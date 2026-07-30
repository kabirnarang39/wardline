package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// bootstrapToken exchanges a presharedsecret registration secret for a
// real bearer token via /credentials/token, failing the test on any
// non-200 response -- a thin wrapper around postCredentialsToken (defined
// in e2e_test.go) for callers that just want the token string.
func bootstrapToken(t *testing.T, listenAddr, secret string) string {
	t.Helper()
	resp := postCredentialsToken(t, listenAddr, secret)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap token for secret %q: expected 200, got %d", secret, resp.StatusCode)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("invalid token response: %v", err)
	}
	if body.Token == "" {
		t.Fatal("expected a non-empty token")
	}
	return body.Token
}

// scimCreateUser provisions a SCIM User via a real HTTP POST to
// /scim/v2/Users and returns its assigned ID (needed to reference it as a
// Group member, since SCIM Group membership is by User ID, not UserName).
func scimCreateUser(t *testing.T, listenAddr, scimToken, userName string) string {
	t.Helper()
	body := fmt.Sprintf(`{"userName":%q,"active":true}`, userName)
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/scim/v2/Users", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+scimToken)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("scim create user %q: expected 201, got %d: %s", userName, resp.StatusCode, b)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("invalid scim user response: %v", err)
	}
	if out.ID == "" {
		t.Fatal("expected a non-empty scim user id")
	}
	return out.ID
}

// scimCreateGroup provisions a SCIM Group (with initial members) via a
// real HTTP POST to /scim/v2/Groups. displayName must follow Wardline's
// group-naming convention (scim/domain.ParseGroupName) for the
// provisioning service to derive an RBAC binding from it.
func scimCreateGroup(t *testing.T, listenAddr, scimToken, displayName string, memberUserIDs []string) {
	t.Helper()
	type member struct {
		Value string `json:"value"`
	}
	members := make([]member, 0, len(memberUserIDs))
	for _, id := range memberUserIDs {
		members = append(members, member{Value: id})
	}
	payload, err := json.Marshal(struct {
		DisplayName string   `json:"displayName"`
		Members     []member `json:"members"`
	}{DisplayName: displayName, Members: members})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/scim/v2/Groups", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+scimToken)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("scim create group %q: expected 201, got %d: %s", displayName, resp.StatusCode, b)
	}
}

// dashboardAuditEntry decodes the fields of dashboard/domain.LiveEntry
// this test cares about -- LiveEntry has no json tags, so its wire shape
// is the Go field names verbatim (see TestServeEndToEnd_AllFeaturesCombined,
// which decodes the same way).
type dashboardAuditEntry struct {
	Identity string
	Tenant   string
	Tool     string
	Decision string
}

func getDashboardAudit(t *testing.T, listenAddr, bearerToken string) []dashboardAuditEntry {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/audit?after=0&limit=1000", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard audit: expected 200, got %d", resp.StatusCode)
	}
	var entries []dashboardAuditEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("invalid dashboard audit JSON: %v", err)
	}
	return entries
}

func getDashboardBlocked(t *testing.T, listenAddr, bearerToken string) []map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/dashboard/api/anomalies/blocked", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard blocked: expected 200, got %d", resp.StatusCode)
	}
	var entries []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("invalid dashboard blocked JSON: %v", err)
	}
	return entries
}

// TestServeEndToEnd_TenantIsolation is the closing test for the whole
// SSO/SCIM + RBAC tenant isolation plan: two tenants (acme and
// widgets-inc) provisioned via real SCIM HTTP calls, identities
// bootstrapped via real credential-issuance bearer tokens (presharedsecret
// bootstrap -- OIDC would need a live IdP this test doesn't have, and
// presharedsecret exercises the identical identity+tenant-resolution path
// through bearerIdentity/VerificationService), driven entirely through
// the real compiled binary over real HTTP, proving:
//
//  1. a tenant-scoped policy rule for acme doesn't leak into widgets-inc
//     -- proven with the SAME identity name ("alice") authenticated into
//     each tenant separately, not just two different people, since a
//     mere identity mismatch (bob vs alice) would deny regardless of
//     whether tenant scoping worked at all;
//  2. widgets-inc's tight budget.tenants override throttles bob well
//     before acme's generous default would throttle alice under
//     identical (two-call) traffic;
//  3. the dashboard's audit view is scoped to the caller's own tenant for
//     a tenant-scoped RoleBinding (alice, bob), and unfiltered (both
//     tenants) for a cluster-bound global admin (root-admin);
//  4. that global admin's binding, and both tenants' admin bindings, are
//     entirely SCIM-provisioned -- rbac.yaml carries zero bindings,
//     proving a SCIM Group with members immediately grants the right
//     RBAC bindings with no rbac.yaml edit;
//  5. an ml_score/auto_block spike driven for identity "shared-name" in
//     acme does not block "shared-name" in widgets-inc (Task 22's
//     regression), exercised end-to-end through the real binary rather
//     than just at the Detector/BlockChecker unit level.
func TestServeEndToEnd_TenantIsolation(t *testing.T) {
	dir := t.TempDir()

	credentialsPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(`
identities:
  - name: alice
    secret: "acme-alice-registration-secret-0001"
    tenant: acme
  - name: alice
    secret: "widgets-alice-registration-secret-0002"
    tenant: widgets-inc
  - name: bob
    secret: "widgets-bob-registration-secret-0003"
    tenant: widgets-inc
  - name: root-admin
    secret: "root-admin-registration-secret-0004"
    tenant: ops
  - name: shared-name
    secret: "acme-shared-registration-secret-0005"
    tenant: acme
  - name: shared-name
    secret: "widgets-shared-registration-secret-0006"
    tenant: widgets-inc
`), 0644); err != nil {
		t.Fatal(err)
	}

	rbacPath := filepath.Join(dir, "rbac.yaml")
	if err := os.WriteFile(rbacPath, []byte(`
# Intentionally no roles/bindings here -- every RBAC grant this test
# relies on (two tenant-scoped admins, one cluster-wide admin) comes from
# SCIM-provisioned groups below (see assertion 4).
`), 0644); err != nil {
		t.Fatal(err)
	}

	anomalyPath := filepath.Join(dir, "anomaly.jsonl")

	const scimToken = "scim-bearer-token-for-e2e-tenant-isolation"
	t.Setenv("WARDLINE_E2E_TENANT_ISOLATION_SCIM_TOKEN", scimToken)

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `
rules:
  - identity: "alice"
    tool: "read_file"
    effect: allow
    tenant: "acme"
  - identity: "bob"
    tool: "list_dir"
    effect: allow
    tenant: "widgets-inc"
  - identity: "shared-name"
    tool: "*"
    effect: allow
    tenant: "acme"
  - identity: "shared-name"
    tool: "*"
    effect: allow
    tenant: "widgets-inc"
default: deny
`, fmt.Sprintf(`features:
  rbac: true
  scim: true
  credential_issuance: true
  anomaly_detection: true
  web_ui: true
  budget_enforcement: true
credential:
  identities_file: "%s"
rbac:
  config_file: "%s"
scim:
  bearer_token_env: "WARDLINE_E2E_TENANT_ISOLATION_SCIM_TOKEN"
budget:
  requests_per_window: 100
  window_seconds: 60
  tenants:
    widgets-inc:
      requests_per_window: 1
      window_seconds: 5
anomaly:
  output: "%s"
  window_seconds: 3
  ml_score:
    enabled: true
    score_threshold: 3.0
    min_calls: 2
  auto_block:
    enabled: true
    score_threshold: 3.0
    block_duration_seconds: 30
`, credentialsPath, rbacPath, anomalyPath))

	// --- Provision two tenants via SCIM: acme (alice, admin) and
	// widgets-inc (bob, admin), plus a cluster-wide admin (root-admin) --
	// all three RBAC grants derived purely from SCIM Group membership,
	// zero rbac.yaml edits (assertion 4).
	aliceID := scimCreateUser(t, addr, scimToken, "alice")
	bobID := scimCreateUser(t, addr, scimToken, "bob")
	rootAdminID := scimCreateUser(t, addr, scimToken, "root-admin")

	scimCreateGroup(t, addr, scimToken, "wardline:tenant-acme:role-admin", []string{aliceID})
	scimCreateGroup(t, addr, scimToken, "wardline:tenant-widgets-inc:role-admin", []string{bobID})
	scimCreateGroup(t, addr, scimToken, "wardline:role-admin", []string{rootAdminID})

	// --- Bootstrap real bearer tokens for every identity this test drives.
	aliceAcmeToken := bootstrapToken(t, addr, "acme-alice-registration-secret-0001")
	aliceWidgetsToken := bootstrapToken(t, addr, "widgets-alice-registration-secret-0002")
	bobToken := bootstrapToken(t, addr, "widgets-bob-registration-secret-0003")
	rootAdminToken := bootstrapToken(t, addr, "root-admin-registration-secret-0004")
	sharedAcmeToken := bootstrapToken(t, addr, "acme-shared-registration-secret-0005")
	sharedWidgetsToken := bootstrapToken(t, addr, "widgets-shared-registration-secret-0006")

	// === Assertion 1: a tenant-scoped policy rule doesn't leak across
	// tenants ===
	allowResp := postToolCallWithBearer(t, addr, aliceAcmeToken, "read_file")
	if allowResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice@acme's policy-allowed call, got %d (stderr: %s)", allowResp.StatusCode, stderr.String())
	}

	// The critical tenant-leak check: the SAME identity name "alice",
	// authenticated into widgets-inc instead of acme, must NOT inherit the
	// acme-scoped allow rule -- if the policy engine ever stopped
	// comparing Tenant, this call would incorrectly succeed. A plain
	// identity mismatch (bob calling alice's rule) wouldn't prove this,
	// since it would deny regardless of whether tenant scoping worked.
	leakResp := postToolCallWithBearer(t, addr, aliceWidgetsToken, "read_file")
	if leakResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for alice@widgets-inc (acme's tenant-scoped rule must not leak), got %d (stderr: %s)", leakResp.StatusCode, stderr.String())
	}

	// bob, calling the identical tool as alice's rule, is denied too (no
	// rule of his own matches read_file).
	bobDeniedResp := postToolCallWithBearer(t, addr, bobToken, "read_file")
	if bobDeniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for bob calling alice's policy-allowed tool, got %d (stderr: %s)", bobDeniedResp.StatusCode, stderr.String())
	}

	// === Assertion 2: budget differs per tenant ===
	// alice@acme has no tenant override -- two calls, both succeed under
	// the generous global default (100/window).
	aliceSecondResp := postToolCallWithBearer(t, addr, aliceAcmeToken, "read_file")
	if aliceSecondResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for alice@acme's second call under acme's generous default budget, got %d (stderr: %s)", aliceSecondResp.StatusCode, stderr.String())
	}

	// bob@widgets-inc, under an identical two-call pattern, is throttled by
	// widgets-inc's tight tenant override (1/window) well before his own
	// identity bucket (also 100/window) would ever kick in.
	bobFirstBudgetResp := postToolCallWithBearer(t, addr, bobToken, "list_dir")
	if bobFirstBudgetResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for bob's first list_dir call, got %d (stderr: %s)", bobFirstBudgetResp.StatusCode, stderr.String())
	}
	bobThrottledResp := postToolCallWithBearer(t, addr, bobToken, "list_dir")
	if bobThrottledResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for bob's second call (widgets-inc's tight tenant budget), got %d (stderr: %s)", bobThrottledResp.StatusCode, stderr.String())
	}

	// === Assertion 3: dashboard views are isolated per tenant ===
	aliceEntries := getDashboardAudit(t, addr, aliceAcmeToken)
	if len(aliceEntries) == 0 {
		t.Fatal("expected at least one audit entry visible to alice")
	}
	for _, e := range aliceEntries {
		if e.Tenant != "acme" {
			t.Errorf("alice (acme, tenant-scoped RoleBinding) saw a non-acme audit entry: %+v", e)
		}
	}

	bobEntries := getDashboardAudit(t, addr, bobToken)
	if len(bobEntries) == 0 {
		t.Fatal("expected at least one audit entry visible to bob")
	}
	for _, e := range bobEntries {
		if e.Tenant != "widgets-inc" {
			t.Errorf("bob (widgets-inc, tenant-scoped RoleBinding) saw a non-widgets-inc audit entry: %+v", e)
		}
	}

	// === Assertion 4: a cluster-bound global admin sees BOTH tenants ===
	rootEntries := getDashboardAudit(t, addr, rootAdminToken)
	seenTenants := map[string]bool{}
	for _, e := range rootEntries {
		seenTenants[e.Tenant] = true
	}
	if !seenTenants["acme"] || !seenTenants["widgets-inc"] {
		t.Fatalf("expected root-admin's global view to include both acme and widgets-inc, saw tenants: %+v", seenTenants)
	}

	// === Assertion 5: an ml_score/auto_block spike in acme must not block
	// the identically-named identity in widgets-inc (Task 22's regression,
	// exercised end-to-end) ===
	//
	// 10 baseline windows, alternating 2 vs 3 calls and 1 vs 2 tools, give
	// shared-name@acme's mlFeatureState real non-zero variance to compare
	// the wild outlier window against -- same shape and reasoning as
	// TestServeEndToEnd_MLScoreAutoBlock, which this mirrors, driven this
	// time through the real bearer-token/tenant path rather than a bare
	// X-Wardline-Identity header.
	for i := 0; i < 5; i++ {
		postToolCallWithBearer(t, addr, sharedAcmeToken, "read_file")
		postToolCallWithBearer(t, addr, sharedAcmeToken, "read_file")
		time.Sleep(3100 * time.Millisecond) // rotate: scores the 2-call window
		postToolCallWithBearer(t, addr, sharedAcmeToken, "read_file")
		postToolCallWithBearer(t, addr, sharedAcmeToken, "list_dir")
		postToolCallWithBearer(t, addr, sharedAcmeToken, "list_dir")
		time.Sleep(3100 * time.Millisecond) // rotate: scores the 3-call window
	}
	// Wild outlier window: many distinct tools in a tight burst.
	for i := 0; i < 30; i++ {
		postToolCallWithBearer(t, addr, sharedAcmeToken, fmt.Sprintf("tool_%d", i))
	}
	time.Sleep(3100 * time.Millisecond)
	// This call's Publish rotates and scores the wild window against the
	// established baseline -- if it clears auto_block.score_threshold,
	// BlockChecker.Block runs synchronously inside it, keyed by
	// (tenant="acme", identity="shared-name"), before this request's own
	// response returns.
	postToolCallWithBearer(t, addr, sharedAcmeToken, "read_file")

	data, err := os.ReadFile(anomalyPath)
	if err != nil {
		t.Fatalf("failed to read anomaly output: %v (stderr: %s)", err, stderr.String())
	}
	if !bytes.Contains(data, []byte(`"kind":"ml_score"`)) {
		t.Fatalf("expected an ml_score anomaly line for shared-name@acme in %s, got: %s", anomalyPath, data)
	}

	blockedAcmeResp := postToolCallWithBearer(t, addr, sharedAcmeToken, "read_file")
	if blockedAcmeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for auto-blocked shared-name@acme, got %d (stderr: %s)", blockedAcmeResp.StatusCode, stderr.String())
	}
	if retryAfter := blockedAcmeResp.Header.Get("Retry-After"); retryAfter == "" {
		t.Error("expected a Retry-After header on shared-name@acme's blocked response")
	}

	// The regression this assertion exists to catch: the identically-named
	// identity in the OTHER tenant must be entirely unaffected.
	notBlockedWidgetsResp := postToolCallWithBearer(t, addr, sharedWidgetsToken, "read_file")
	if notBlockedWidgetsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for shared-name@widgets-inc (must not inherit acme's auto-block), got %d (stderr: %s)", notBlockedWidgetsResp.StatusCode, stderr.String())
	}

	// Cross-check via the dashboard's blocked-list view too, through the
	// global root-admin so both tenants are visible in one call.
	blockedList := getDashboardBlocked(t, addr, rootAdminToken)
	var sawAcmeBlock, sawWidgetsBlock bool
	for _, e := range blockedList {
		if e["identity"] == "shared-name" {
			switch e["tenant"] {
			case "acme":
				sawAcmeBlock = true
			case "widgets-inc":
				sawWidgetsBlock = true
			}
		}
	}
	if !sawAcmeBlock {
		t.Errorf("expected shared-name@acme in /dashboard/api/anomalies/blocked, got %+v", blockedList)
	}
	if sawWidgetsBlock {
		t.Errorf("shared-name@widgets-inc must not appear in the blocked list -- auto-block leaked across tenants: %+v", blockedList)
	}
}
