package adapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	approvaldomain "github.com/kabirnarang39/wardline/internal/features/approval/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	compliancedomain "github.com/kabirnarang39/wardline/internal/features/compliance/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	federationdomain "github.com/kabirnarang39/wardline/internal/features/federation/domain"
	federationusecase "github.com/kabirnarang39/wardline/internal/features/federation/usecase"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
)

type fakeAuditSource struct {
	entries []domain.LiveEntry
}

func (f *fakeAuditSource) Since(afterID int64, limit int, tenantFilter string) []domain.LiveEntry {
	var out []domain.LiveEntry
	for _, e := range f.entries {
		if e.ID <= afterID {
			continue
		}
		if tenantFilter != "" && e.Tenant != tenantFilter {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

type fakeStatusSource struct {
	status domain.StatusInfo
}

func (f *fakeStatusSource) Status() domain.StatusInfo {
	return f.status
}

type fakeAnomalySource struct {
	entries []usecase.Alert
}

func (f *fakeAnomalySource) Since(afterID int64, limit int, tenantFilter string) []usecase.Alert {
	if tenantFilter == "" {
		return f.entries
	}
	var out []usecase.Alert
	for _, a := range f.entries {
		if a.Tenant == tenantFilter {
			out = append(out, a)
		}
	}
	return out
}

type fakeFederationSource struct {
	entries []federationusecase.CorrelatedAlertEntry
}

func (f *fakeFederationSource) Since(afterID int64, limit int) []federationusecase.CorrelatedAlertEntry {
	return f.entries
}

type fakeBlockedSource struct {
	entries []anomalydomain.BlockedEntry

	lastUnblockIdentity string
	lastUnblockTenant   string
	unblockResult       bool
}

func (f *fakeBlockedSource) List(tenantFilter string) []anomalydomain.BlockedEntry {
	if tenantFilter == "" {
		return f.entries
	}
	var out []anomalydomain.BlockedEntry
	for _, e := range f.entries {
		if e.Tenant == tenantFilter {
			out = append(out, e)
		}
	}
	return out
}

// Unblock records the (identity, tenantName) it was called with -- tests
// assert against lastUnblockIdentity/lastUnblockTenant rather than
// mutating f.entries, since Handler's own routing/authorization/tenant-
// resolution logic is what's under test here, not BlockChecker's real
// delete semantics (already covered by Task 8's usecase-layer tests).
// unblockResult lets a test control the 404-vs-204 branch.
func (f *fakeBlockedSource) Unblock(identity, tenantName string) bool {
	f.lastUnblockIdentity = identity
	f.lastUnblockTenant = tenantName
	return f.unblockResult
}

// denyAllUnblockAuthorizer and allowAllUnblockAuthorizer are the
// UnblockAuthorizer equivalents of this file's fakeTenantScopeResolver
// pattern -- fixed-answer stubs for exercising Handler's own gating logic
// without needing a real rbac wiring.
type denyAllUnblockAuthorizer struct{}

func (denyAllUnblockAuthorizer) AllowedFor(r *http.Request, targetTenant string) bool { return false }

type allowAllUnblockAuthorizer struct{}

func (allowAllUnblockAuthorizer) AllowedFor(r *http.Request, targetTenant string) bool { return true }

// allowReloadAuthorizer and denyReloadAuthorizer are the ReloadAuthorizer
// equivalents of allowAllUnblockAuthorizer/denyAllUnblockAuthorizer above
// -- fixed-answer stubs for exercising handleReload's own routing/gating
// logic without needing a real rbac wiring. allowReloadAuthorizer also
// returns a settable identity, standing in for the caller identity a real
// Authorize would resolve.
type allowReloadAuthorizer struct{ identity string }

func (a allowReloadAuthorizer) Authorize(r *http.Request) (string, bool) { return a.identity, true }

type denyReloadAuthorizer struct{}

func (denyReloadAuthorizer) Authorize(r *http.Request) (string, bool) { return "", false }

// fakePolicyWriter is a settable stub for adapter.PolicyWriter -- records
// the last call it received (so a test can assert appliedBy came from
// the ReloadAuthorizer, never the request body) and returns a settable
// error, matching this file's established fake-with-a-spy pattern.
type fakePolicyWriter struct {
	err           error
	lastRules     []policydomain.Rule
	lastDefault   policydomain.Effect
	lastAppliedBy string
}

func (f *fakePolicyWriter) WriteAndReload(rules []policydomain.Rule, def policydomain.Effect, appliedBy string) error {
	f.lastRules = rules
	f.lastDefault = def
	f.lastAppliedBy = appliedBy
	return f.err
}

// fakeBudgetWriter is fakePolicyWriter's exact equivalent for
// adapter.BudgetWriter.
type fakeBudgetWriter struct {
	err                 error
	lastDefault         budgetdomain.LimitInfo
	lastTenantOverrides []budgetdomain.OverrideInfo
	lastToolOverrides   []budgetdomain.OverrideInfo
	lastAppliedBy       string
}

func (f *fakeBudgetWriter) WriteAndReload(def budgetdomain.LimitInfo, tenantOverrides, toolOverrides []budgetdomain.OverrideInfo, appliedBy string) error {
	f.lastDefault = def
	f.lastTenantOverrides = tenantOverrides
	f.lastToolOverrides = toolOverrides
	f.lastAppliedBy = appliedBy
	return f.err
}

// recordingUnblockAuthorizer is a spy on top of allowAllUnblockAuthorizer's
// always-allow behavior: it records the targetTenant it was called with,
// so a test can prove handleUnblock resolves targetTenant (h.tenantFilter
// or ?tenant=) BEFORE calling AllowedFor, and passes that exact value
// through -- not, e.g., the raw unresolved query parameter or "".
type recordingUnblockAuthorizer struct {
	lastTargetTenant string
}

func (r *recordingUnblockAuthorizer) AllowedFor(req *http.Request, targetTenant string) bool {
	r.lastTargetTenant = targetTenant
	return true
}

// fakeTenantScopeResolver is a settable stub for adapter.TenantScopeResolver
// -- returns tenant for every request regardless of what the request
// itself carries, matching the real closure's semantics (derived from the
// resolved caller identity only).
type fakeTenantScopeResolver struct {
	tenant string
}

func (f fakeTenantScopeResolver) TenantFilter(r *http.Request) string {
	return f.tenant
}

// fakeCallerInfoResolver is a settable stub for adapter.CallerInfoResolver,
// matching fakeTenantScopeResolver's exact pattern immediately above.
type fakeCallerInfoResolver struct {
	identity      string
	canConfigEdit bool
}

func (f fakeCallerInfoResolver) CallerInfo(r *http.Request) (string, bool) {
	return f.identity, f.canConfigEdit
}

// fakeRBACSource is a settable stub for adapter.RBACSource -- returns
// fixed roles/bindings regardless of what the request carries, matching
// this file's other fake*Source structs.
type fakeRBACSource struct {
	roles               []rbacdomain.Role
	clusterRoleBindings []rbacdomain.ClusterRoleBinding
	roleBindings        []rbacdomain.RoleBinding
}

func (f *fakeRBACSource) Roles() []rbacdomain.Role { return f.roles }

func (f *fakeRBACSource) ClusterRoleBindings() []rbacdomain.ClusterRoleBinding {
	return f.clusterRoleBindings
}

func (f *fakeRBACSource) RoleBindings() []rbacdomain.RoleBinding { return f.roleBindings }

// fakeBudgetSource is a settable stub for adapter.BudgetSource -- returns
// fixed default/overrides regardless of what the request carries,
// matching this file's other fake*Source structs.
type fakeBudgetSource struct {
	defaultLimit    budgetdomain.LimitInfo
	tenantOverrides []budgetdomain.OverrideInfo
	toolOverrides   []budgetdomain.OverrideInfo
}

func (f *fakeBudgetSource) DefaultLimit() budgetdomain.LimitInfo { return f.defaultLimit }

func (f *fakeBudgetSource) TenantOverrides() []budgetdomain.OverrideInfo { return f.tenantOverrides }

func (f *fakeBudgetSource) ToolOverrides() []budgetdomain.OverrideInfo { return f.toolOverrides }

func testAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {Data: []byte(`<!doctype html><div id="app">wardline dashboard</div>`)},
		"app.js":     {Data: []byte(`console.log("app");`)},
	}
}

func TestHandler_AuditEndpoint_ReturnsJSON(t *testing.T) {
	audit := &fakeAuditSource{entries: []domain.LiveEntry{
		{ID: 1, Identity: "agent-1", Tool: "read_file", Decision: "allow"},
		{ID: 2, Identity: "agent-2", Tool: "write_file", Decision: "deny"},
	}}
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit?after=0&limit=10", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []domain.LiveEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v; body=%s", err, rec.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
}

func TestHandler_AuditEndpoint_BadQueryParamsDefaultSanely(t *testing.T) {
	audit := &fakeAuditSource{entries: []domain.LiveEntry{{ID: 1, Identity: "agent-1"}}}
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit?after=not-a-number&limit=also-not-a-number", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (bad params should default, not 500); body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandler_AuditEndpoint_LimitClampedToMax(t *testing.T) {
	entries := make([]domain.LiveEntry, 1200)
	for i := range entries {
		entries[i] = domain.LiveEntry{ID: int64(i + 1), Identity: "agent-1"}
	}
	audit := &fakeAuditSource{entries: entries}
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit?after=0&limit=5000", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []domain.LiveEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v; body=%s", err, rec.Body.String())
	}
	if len(got) != 1000 {
		t.Fatalf("expected limit clamped to 1000, got %d entries", len(got))
	}
}

func TestHandler_PolicyEndpoint_ReturnsJSON(t *testing.T) {
	policy := domain.PolicyInfo{Backend: "yaml", Source: "rules: []\ndefault: deny\n"}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, policy, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got domain.PolicyInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Backend != "yaml" || got.Source != policy.Source {
		t.Errorf("got %+v, want %+v", got, policy)
	}
}

func TestHandler_StatusEndpoint_ReturnsJSON(t *testing.T) {
	status := domain.StatusInfo{Version: "0.5.0-dev", UptimeSeconds: 42, Listen: ":8080", Upstream: "http://localhost:9000", Features: map[string]bool{"web_ui": true}}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{status: status}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got domain.StatusInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Version != "0.5.0-dev" || got.UptimeSeconds != 42 {
		t.Errorf("got %+v, want %+v", got, status)
	}
}

// TestHandler_HandleStatus_IncludesCallerTenant proves handleStatus's
// widened response (Task 5) carries a per-request CallerTenant derived
// from h.tenantFilter, alongside the still-embedded domain.StatusInfo
// fields.
func TestHandler_HandleStatus_IncludesCallerTenant(t *testing.T) {
	status := &fakeStatusSource{status: domain.StatusInfo{Version: "test"}}
	scope := fakeTenantScopeResolver{tenant: "acme"}
	h := adapter.NewHandler(&fakeAuditSource{}, status, domain.PolicyInfo{}, testAssets(), nil, nil, nil, scope, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var got struct {
		domain.StatusInfo
		CallerTenant string
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.CallerTenant != "acme" {
		t.Errorf("CallerTenant = %q, want %q", got.CallerTenant, "acme")
	}
	if got.Version != "test" {
		t.Errorf("Version = %q, want %q (StatusInfo fields must still be embedded)", got.Version, "test")
	}
}

// TestHandler_HandleStatus_CallerTenantEmptyWhenScopeNil proves the
// "rbac off" half of the contract: CallerTenant is empty when h.scope is
// nil, matching h.tenantFilter's own nil-scope behavior.
func TestHandler_HandleStatus_CallerTenantEmptyWhenScopeNil(t *testing.T) {
	status := &fakeStatusSource{status: domain.StatusInfo{Version: "test"}}
	h := adapter.NewHandler(&fakeAuditSource{}, status, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var got struct {
		domain.StatusInfo
		CallerTenant string
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.CallerTenant != "" {
		t.Errorf("CallerTenant = %q, want empty when rbac is off (scope nil)", got.CallerTenant)
	}
}

// TestHandler_HandleStatus_IncludesCallerIdentity proves handleStatus's
// response also carries the per-request CallerIdentity/CallerCanConfigEdit
// pair derived from h.callerInfo, for the dashboard topbar's identity
// display -- same "widened response, still embeds StatusInfo" contract
// as CallerTenant above, independent of it.
func TestHandler_HandleStatus_IncludesCallerIdentity(t *testing.T) {
	status := &fakeStatusSource{status: domain.StatusInfo{Version: "test"}}
	info := fakeCallerInfoResolver{identity: "r.narang@acme", canConfigEdit: true}
	h := adapter.NewHandler(&fakeAuditSource{}, status, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, info, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var got struct {
		domain.StatusInfo
		CallerIdentity      string
		CallerCanConfigEdit bool
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.CallerIdentity != "r.narang@acme" {
		t.Errorf("CallerIdentity = %q, want %q", got.CallerIdentity, "r.narang@acme")
	}
	if !got.CallerCanConfigEdit {
		t.Error("CallerCanConfigEdit = false, want true")
	}
}

// TestHandler_HandleStatus_CallerIdentityEmptyWhenResolverNil proves the
// "rbac off" half of the contract: CallerIdentity/CallerCanConfigEdit are
// zero-valued when h.callerInfo is nil, matching CallerTenant's own
// nil-scope behavior -- the topbar must never fabricate a name.
func TestHandler_HandleStatus_CallerIdentityEmptyWhenResolverNil(t *testing.T) {
	status := &fakeStatusSource{status: domain.StatusInfo{Version: "test"}}
	h := adapter.NewHandler(&fakeAuditSource{}, status, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var got struct {
		domain.StatusInfo
		CallerIdentity      string
		CallerCanConfigEdit bool
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.CallerIdentity != "" {
		t.Errorf("CallerIdentity = %q, want empty when callerInfo is nil (rbac off)", got.CallerIdentity)
	}
	if got.CallerCanConfigEdit {
		t.Error("CallerCanConfigEdit = true, want false when callerInfo is nil (rbac off)")
	}
}

func TestHandler_ServesKnownStaticAsset(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/app.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `console.log("app");` {
		t.Errorf("body = %q, want %q", got, `console.log("app");`)
	}
}

func TestHandler_UnknownPathFallsBackToIndexHTML(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/some/unknown/client/route", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SPA fallback)", rec.Code)
	}
	if got := rec.Body.String(); got != `<!doctype html><div id="app">wardline dashboard</div>` {
		t.Errorf("expected index.html fallback body, got %q", got)
	}
}

func TestHandler_JSONEndpoints_RejectNonGETMethods(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	for _, path := range []string{"/dashboard/api/audit", "/dashboard/api/policy", "/dashboard/api/status"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: POST status = %d, want 405", path, rec.Code)
		}
	}
}

func TestHandler_ResponsesCarrySecurityHeaders(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	for _, path := range []string{"/dashboard/api/audit", "/dashboard/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		wantCSP := "default-src 'self'; frame-ancestors 'none'"
		if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
			t.Errorf("%s: Content-Security-Policy = %q, want %q", path, got, wantCSP)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, got)
		}
	}
}

func TestHandler_RootServesIndexHTML(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `<!doctype html><div id="app">wardline dashboard</div>` {
		t.Errorf("body = %q", got)
	}
}

func TestHandler_HandleAnomalies_ReturnsBufferedEntriesAsJSON(t *testing.T) {
	anomalies := &fakeAnomalySource{entries: []usecase.Alert{
		{ID: 1, Anomaly: anomalydomain.Anomaly{
			Timestamp: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
			Identity:  "alice",
			Tenant:    "acme",
			Kind:      anomalydomain.KindNovelTool,
			Detail:    "first call from this identity to tool read_file",
			Entry:     auditdomain.Entry{Tool: "read_file"},
		}},
	}}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []domain.AnomalyEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	// I5 regression: Tenant must round-trip through the wire shape, not
	// be dropped even though it's available on the source Alert.
	if len(got) != 1 || got[0].Identity != "alice" || got[0].Tenant != "acme" || got[0].Kind != "novel_tool" || got[0].Tool != "read_file" {
		t.Errorf("unexpected decoded response: %+v", got)
	}
}

func TestHandler_HandleAnomalies_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when anomalies is not wired (feature off), got %d", rec.Code)
	}
}

func TestHandler_HandleRBAC_ReturnsRolesAndBindingsAsJSON(t *testing.T) {
	rbac := &fakeRBACSource{
		roles: []rbacdomain.Role{
			{Name: "admin", Permissions: []rbacdomain.Permission{rbacdomain.PermissionDashboardView, rbacdomain.PermissionCredentialRevoke}},
			{Name: "viewer", Permissions: []rbacdomain.Permission{rbacdomain.PermissionDashboardView}},
		},
		clusterRoleBindings: []rbacdomain.ClusterRoleBinding{
			{Subject: "alice", RoleName: "admin"},
		},
		roleBindings: []rbacdomain.RoleBinding{
			{Subject: "bob", RoleName: "viewer", Tenant: "acme"},
			{Subject: "carol", RoleName: "viewer", Tenant: "globex"},
		},
	}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, rbac, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/rbac", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Roles    []domain.RoleEntry    `json:"roles"`
		Bindings []domain.BindingEntry `json:"bindings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d: %+v", len(got.Roles), got.Roles)
	}
	if got.Roles[0].Name != "admin" || got.Roles[0].BindingCount != 1 || len(got.Roles[0].Permissions) != 2 {
		t.Errorf("admin role entry = %+v, want BindingCount=1, 2 permissions", got.Roles[0])
	}
	if got.Roles[1].Name != "viewer" || got.Roles[1].BindingCount != 2 {
		t.Errorf("viewer role entry = %+v, want BindingCount=2 (bob's and carol's role bindings both reference viewer)", got.Roles[1])
	}
	if len(got.Bindings) != 3 {
		t.Fatalf("expected 3 bindings (1 cluster + 2 role), got %d: %+v", len(got.Bindings), got.Bindings)
	}
	var aliceBinding, bobBinding *domain.BindingEntry
	for i := range got.Bindings {
		switch got.Bindings[i].Subject {
		case "alice":
			aliceBinding = &got.Bindings[i]
		case "bob":
			bobBinding = &got.Bindings[i]
		}
	}
	if aliceBinding == nil || aliceBinding.Role != "admin" || aliceBinding.Tenant != "" {
		t.Errorf("alice binding = %+v, want role=admin tenant=\"\" (cluster-scoped)", aliceBinding)
	}
	if bobBinding == nil || bobBinding.Role != "viewer" || bobBinding.Tenant != "acme" {
		t.Errorf("bob binding = %+v, want role=viewer tenant=acme", bobBinding)
	}
}

func TestHandler_HandleRBAC_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/rbac", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when rbac is not wired (feature off), got %d", rec.Code)
	}
}

func TestHandler_HandleBudget_ReturnsDefaultAndOverridesAsJSON(t *testing.T) {
	budget := &fakeBudgetSource{
		defaultLimit: budgetdomain.LimitInfo{RequestsPerWindow: 25, Window: 60 * time.Second},
		tenantOverrides: []budgetdomain.OverrideInfo{
			{Scope: "tenant", Name: "globex", LimitInfo: budgetdomain.LimitInfo{RequestsPerWindow: 10, Window: 60 * time.Second}},
		},
		toolOverrides: []budgetdomain.OverrideInfo{
			{Scope: "tool", Name: "run_query", LimitInfo: budgetdomain.LimitInfo{RequestsPerWindow: 15, Window: 30 * time.Second}},
		},
	}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, budget, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/budget", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Default   domain.BudgetDefaultEntry    `json:"default"`
		Overrides []domain.BudgetOverrideEntry `json:"overrides"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got.Default.RequestsPerWindow != 25 || got.Default.WindowSeconds != 60 {
		t.Errorf("default = %+v, want {25 60}", got.Default)
	}
	if len(got.Overrides) != 2 {
		t.Fatalf("expected 2 overrides (1 tenant + 1 tool), got %d: %+v", len(got.Overrides), got.Overrides)
	}
	var tenantOverride, toolOverride *domain.BudgetOverrideEntry
	for i := range got.Overrides {
		switch got.Overrides[i].Scope {
		case "tenant":
			tenantOverride = &got.Overrides[i]
		case "tool":
			toolOverride = &got.Overrides[i]
		}
	}
	if tenantOverride == nil || tenantOverride.Name != "globex" || tenantOverride.RequestsPerWindow != 10 || tenantOverride.WindowSeconds != 60 {
		t.Errorf("tenant override = %+v, want name=globex limit=10 window=60", tenantOverride)
	}
	if toolOverride == nil || toolOverride.Name != "run_query" || toolOverride.RequestsPerWindow != 15 || toolOverride.WindowSeconds != 30 {
		t.Errorf("tool override = %+v, want name=run_query limit=15 window=30", toolOverride)
	}
}

func TestHandler_HandleBudget_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/budget", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when budget is not wired (feature off), got %d", rec.Code)
	}
}

func TestHandler_HandleFederationCorrelated_ReturnsBufferedEntriesAsJSON(t *testing.T) {
	federation := &fakeFederationSource{entries: []federationusecase.CorrelatedAlertEntry{
		{ID: 1, CorrelatedAlert: federationdomain.CorrelatedAlert{
			Fingerprint: "fp1",
			Kind:        anomalydomain.KindRateSpike,
			InstanceIDs: []string{"eu-cluster", "us-cluster"},
		}},
	}}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, federation, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/federation/correlated", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []domain.CorrelatedAlertEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got) != 1 || got[0].Fingerprint != "fp1" || got[0].Kind != string(anomalydomain.KindRateSpike) {
		t.Errorf("unexpected decoded response: %+v", got)
	}
	if len(got[0].InstanceIDs) != 2 {
		t.Errorf("expected 2 instance ids, got %+v", got[0].InstanceIDs)
	}
	// The raw response body must be snake_case, not the usecase type's
	// Go-cased fields -- proves the dashboard's own wire shape is what's
	// actually on the wire, not just that it round-trips.
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"instance_ids"`)) {
		t.Errorf("expected snake_case \"instance_ids\" in response body, got %s", rec.Body.String())
	}
}

func TestHandler_HandleFederationCorrelated_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/federation/correlated", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when federation is not wired (feature off), got %d", rec.Code)
	}
}

func TestHandler_HandleBlocked_ReturnsListAsJSON(t *testing.T) {
	until := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	blocked := &fakeBlockedSource{entries: []anomalydomain.BlockedEntry{
		{Identity: "alice", BlockedUntil: until, Reason: "rate_spike"},
	}}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies/blocked", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []anomalydomain.BlockedEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got) != 1 || got[0].Identity != "alice" || got[0].Reason != "rate_spike" || !got[0].BlockedUntil.Equal(until) {
		t.Errorf("unexpected decoded response: %+v", got)
	}
}

func TestHandler_HandleBlocked_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies/blocked", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when blocked is not wired (feature off), got %d", rec.Code)
	}
}

// --- Task 23: tenant-filtered dashboard views ---

func tenantScopedFixtures() (*fakeAuditSource, *fakeAnomalySource, *fakeBlockedSource) {
	audit := &fakeAuditSource{entries: []domain.LiveEntry{
		{ID: 1, Identity: "alice", Tenant: "acme", Tool: "read_file"},
		{ID: 2, Identity: "bob", Tenant: "widgets-inc", Tool: "write_file"},
	}}
	anomalies := &fakeAnomalySource{entries: []usecase.Alert{
		{ID: 1, Anomaly: anomalydomain.Anomaly{Identity: "alice", Tenant: "acme", Kind: anomalydomain.KindNovelTool}},
		{ID: 2, Anomaly: anomalydomain.Anomaly{Identity: "bob", Tenant: "widgets-inc", Kind: anomalydomain.KindRateSpike}},
	}}
	blocked := &fakeBlockedSource{entries: []anomalydomain.BlockedEntry{
		{Identity: "alice", Tenant: "acme", Reason: "rate_spike"},
		{Identity: "bob", Tenant: "widgets-inc", Reason: "rate_spike"},
	}}
	return audit, anomalies, blocked
}

// TestHandler_TenantScopedCaller_OnlySeesOwnTenant proves property (1):
// a tenant-scoped caller (scope.TenantFilter returns a non-empty tenant)
// never sees another tenant's audit, anomaly, or blocked entries across
// every endpoint Task 23 touches.
func TestHandler_TenantScopedCaller_OnlySeesOwnTenant(t *testing.T) {
	audit, anomalies, blocked := tenantScopedFixtures()
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, fakeTenantScopeResolver{tenant: "acme"}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var gotAudit []domain.LiveEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &gotAudit); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(gotAudit) != 1 || gotAudit[0].Identity != "alice" {
		t.Fatalf("tenant-scoped caller's /api/audit = %+v, want only acme's alice entry", gotAudit)
	}

	req = httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var gotAnomalies []domain.AnomalyEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &gotAnomalies); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(gotAnomalies) != 1 || gotAnomalies[0].Identity != "alice" {
		t.Fatalf("tenant-scoped caller's /api/anomalies = %+v, want only acme's alice entry", gotAnomalies)
	}

	req = httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies/blocked", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var gotBlocked []anomalydomain.BlockedEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &gotBlocked); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(gotBlocked) != 1 || gotBlocked[0].Identity != "alice" {
		t.Fatalf("tenant-scoped caller's /api/anomalies/blocked = %+v, want only acme's alice entry", gotBlocked)
	}
}

// TestHandler_GloballyGrantedCaller_SeesAllTenants proves property (2):
// a globally-granted caller (scope.TenantFilter returns "") sees every
// tenant's entries, unfiltered -- today's behavior, preserved.
func TestHandler_GloballyGrantedCaller_SeesAllTenants(t *testing.T) {
	audit, anomalies, blocked := tenantScopedFixtures()
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, fakeTenantScopeResolver{tenant: ""}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var gotAudit []domain.LiveEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &gotAudit); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(gotAudit) != 2 {
		t.Fatalf("globally-granted caller's /api/audit = %+v, want both tenants' entries", gotAudit)
	}
}

// TestHandler_NilScopeResolver_Unfiltered proves rbac-off parity: when
// Handler is constructed with a nil TenantScopeResolver (rbac disabled
// entirely, matching every pre-Task-23 NewHandler call site in this
// file), every endpoint stays unfiltered exactly as before this task.
func TestHandler_NilScopeResolver_Unfiltered(t *testing.T) {
	audit, anomalies, blocked := tenantScopedFixtures()
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var gotAudit []domain.LiveEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &gotAudit); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(gotAudit) != 2 {
		t.Fatalf("nil-scope /api/audit = %+v, want both tenants' entries (rbac off => unfiltered)", gotAudit)
	}
}

// TestHandler_TenantFilterIgnoresClientSuppliedTenantParam is the core
// IDOR regression test: a tenant-scoped caller cannot widen or redirect
// their own filter by supplying a "tenant" query parameter (or any other
// client-controlled input) naming a different tenant. The filter must
// come only from scope.TenantFilter (derived from the RBAC-resolved
// caller identity), never from r.URL.Query() or headers.
func TestHandler_TenantFilterIgnoresClientSuppliedTenantParam(t *testing.T) {
	audit, anomalies, blocked := tenantScopedFixtures()
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, fakeTenantScopeResolver{tenant: "acme"}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/audit?tenant=widgets-inc", nil)
	req.Header.Set("X-Tenant", "widgets-inc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var got []domain.LiveEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got) != 1 || got[0].Identity != "alice" {
		t.Fatalf("client-supplied tenant param/header must be ignored -- got %+v, want only acme's alice entry", got)
	}
}

// TestHandler_FederationRoute_StaysUnfiltered proves property (3): the
// federation correlated-alerts view is untouched by Task 23 -- it has no
// tenantFilter parameter at all (FederationSource.Since's signature is
// unchanged) and returns every tenant's correlated alerts regardless of
// what scope.TenantFilter resolves to, matching the design spec's
// explicit call-out that federation's own tenant filtering is a future
// cycle's work, not this task's.
func TestHandler_FederationRoute_StaysUnfiltered(t *testing.T) {
	federation := &fakeFederationSource{entries: []federationusecase.CorrelatedAlertEntry{
		{ID: 1, CorrelatedAlert: federationdomain.CorrelatedAlert{Fingerprint: "fp1", InstanceIDs: []string{"eu-cluster"}}},
		{ID: 2, CorrelatedAlert: federationdomain.CorrelatedAlert{Fingerprint: "fp2", InstanceIDs: []string{"us-cluster"}}},
	}}
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, federation, nil, fakeTenantScopeResolver{tenant: "acme"}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/federation/correlated", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var got []domain.CorrelatedAlertEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("federation route must stay unfiltered even with a tenant-scoped caller -- got %+v, want both entries", got)
	}
}

// --- Task 9: DELETE /dashboard/api/anomalies/blocked/{identity} manual unblock ---

func TestHandler_UnblockRoute_RequiresUnblockAuthorizer(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	scope := fakeTenantScopeResolver{tenant: "acme"}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, denyAllUnblockAuthorizer{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 when UnblockAuthorizer denies, got %d", rec.Code)
	}
}

func TestHandler_UnblockRoute_CallsUnblockWithResolvedTenant(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	scope := fakeTenantScopeResolver{tenant: "acme"}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d", rec.Code)
	}
	if blocked.lastUnblockIdentity != "alice" || blocked.lastUnblockTenant != "acme" {
		t.Errorf("Unblock called with (%q,%q), want (\"alice\",\"acme\")", blocked.lastUnblockIdentity, blocked.lastUnblockTenant)
	}
}

// TestHandler_UnblockRoute_UnfilteredCallerWithoutTenantParam_Returns400
// proves the design-resolution's core rule: a caller whose tenantFilter
// resolves to "" (rbac off, or a global/IsGlobal grant -- both already
// carry cross-tenant authority) must name the target tenant explicitly
// via ?tenant=; without it, this is a 400, never a silent no-op and never
// an attempt to unblock a literal empty-string tenant.
func TestHandler_UnblockRoute_UnfilteredCallerWithoutTenantParam_Returns400(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	scope := fakeTenantScopeResolver{tenant: ""}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 when an unfiltered-authority caller supplies no ?tenant=, got %d", rec.Code)
	}
	if blocked.lastUnblockIdentity != "" {
		t.Errorf("Unblock must not be called at all -- got identity %q", blocked.lastUnblockIdentity)
	}
}

// TestHandler_UnblockRoute_UnfilteredCallerWithTenantParam_Succeeds is the
// same unfiltered-authority caller as above, but WITH ?tenant=widgets-inc
// -- proves the query param is honored ONLY in this unfiltered-authority
// case, never overriding a scoped caller's own tenant (see the other
// tests in this section for that half of the property).
func TestHandler_UnblockRoute_UnfilteredCallerWithTenantParam_Succeeds(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	scope := fakeTenantScopeResolver{tenant: ""}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice?tenant=widgets-inc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if blocked.lastUnblockIdentity != "alice" || blocked.lastUnblockTenant != "widgets-inc" {
		t.Errorf("Unblock called with (%q,%q), want (\"alice\",\"widgets-inc\")", blocked.lastUnblockIdentity, blocked.lastUnblockTenant)
	}
}

// TestHandler_UnblockRoute_AllowedForReceivesResolvedTargetTenant proves
// handleUnblock resolves targetTenant (h.tenantFilter, or ?tenant= for an
// unfiltered-authority caller) BEFORE calling AllowedFor, and passes that
// exact resolved value through -- the C1 fix's ordering requirement (final
// review: "call AllowedFor(r, targetTenant) AFTER resolving targetTenant,
// not before").
func TestHandler_UnblockRoute_AllowedForReceivesResolvedTargetTenant(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	scope := fakeTenantScopeResolver{tenant: ""}
	authz := &recordingUnblockAuthorizer{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, authz, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice?tenant=widgets-inc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if authz.lastTargetTenant != "widgets-inc" {
		t.Errorf("AllowedFor called with targetTenant %q, want %q", authz.lastTargetTenant, "widgets-inc")
	}
}

func TestHandler_UnblockRoute_NilBlockedOrUnblock_Returns404(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when blocked/unblock are not wired (feature off or rbac off), got %d", rec.Code)
	}
}

func TestHandler_UnblockRoute_NonDeleteMethod_Returns405(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, nil, allowAllUnblockAuthorizer{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies/blocked/alice", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for non-DELETE method, got %d", rec.Code)
	}
}

// TestHandler_UnblockRoute_TenantFilterIgnoresClientSuppliedTenantParam is
// the unblock route's own IDOR regression test, mirroring
// TestHandler_TenantFilterIgnoresClientSuppliedTenantParam for /api/audit:
// a tenant-scoped caller (fakeTenantScopeResolver{tenant: "acme"}) cannot
// widen or redirect their own unblock target by supplying a "tenant" query
// parameter naming a different tenant. h.tenantFilter(r) -- derived only
// from the RBAC-resolved caller identity -- must win; ?tenant= is honored
// only for an unfiltered-authority caller (see the tests above), never to
// override a scoped caller's own tenant.
func TestHandler_UnblockRoute_TenantFilterIgnoresClientSuppliedTenantParam(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	scope := fakeTenantScopeResolver{tenant: "acme"}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice?tenant=widgets-inc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if blocked.lastUnblockIdentity != "alice" || blocked.lastUnblockTenant != "acme" {
		t.Errorf("client-supplied ?tenant= must be ignored for a scoped caller -- Unblock called with (%q,%q), want (\"alice\",\"acme\")", blocked.lastUnblockIdentity, blocked.lastUnblockTenant)
	}
}

// --- Task 5: POST /dashboard/api/reload/{domain} ---

func TestHandler_ReloadRoute_NonPostMethod_Returns405(t *testing.T) {
	coordinator := &reload.ReloadCoordinator{Reloaders: map[string]func() error{}, OnAudit: func(reload.ReloadResult) {}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, coordinator, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/reload/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for non-POST method, got %d", rec.Code)
	}
}

// TestHandler_ReloadRoute_NilCoordinatorOrAuth_Returns404 covers both nil
// halves of the pair, mirroring TestHandler_UnblockRoute_NilBlockedOrUnblock_Returns404:
// reload is unavailable (404, not merely ungated) whenever either the
// coordinator or its authorizer isn't wired -- e.g. rbac is off, since
// reloadAuth is nil in that case (see newReloadAuthorizer's wiring in
// main.go).
func TestHandler_ReloadRoute_NilCoordinatorOrAuth_Returns404(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when reload is not wired (feature off or rbac off), got %d", rec.Code)
	}
}

func TestHandler_ReloadRoute_EmptyDomain_Returns400(t *testing.T) {
	coordinator := &reload.ReloadCoordinator{Reloaders: map[string]func() error{}, OnAudit: func(reload.ReloadResult) {}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, coordinator, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 when domain is empty, got %d", rec.Code)
	}
}

// TestHandler_ReloadRoute_AuthorizerDenies_Returns403 also proves the
// coordinator is never reached when ReloadAuthorizer denies -- the
// registered reloader panics if invoked.
func TestHandler_ReloadRoute_AuthorizerDenies_Returns403(t *testing.T) {
	coordinator := &reload.ReloadCoordinator{
		Reloaders: map[string]func() error{"policy": func() error { panic("must not be called when denied") }},
		OnAudit:   func(reload.ReloadResult) {},
	}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, coordinator, denyReloadAuthorizer{}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 when ReloadAuthorizer denies, got %d", rec.Code)
	}
}

// TestHandler_ReloadRoute_Success_ReturnsResultWithAppliedByFromAuthorizer
// proves AppliedBy comes from ReloadAuthorizer.Authorize's resolved
// identity, never from anything the client supplies (no request body or
// query parameter names it here).
func TestHandler_ReloadRoute_Success_ReturnsResultWithAppliedByFromAuthorizer(t *testing.T) {
	coordinator := &reload.ReloadCoordinator{
		Reloaders: map[string]func() error{"policy": func() error { return nil }},
		OnAudit:   func(reload.ReloadResult) {},
	}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, coordinator, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got reload.ReloadResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !got.OK || got.Domain != "policy" || got.AppliedBy != "alice" {
		t.Errorf("got %+v, want OK=true Domain=policy AppliedBy=alice", got)
	}
}

// TestHandler_ReloadRoute_UnknownDomain_ReturnsOKFalseNot404 proves an
// unknown domain is the coordinator's own rejected-result path (OK=false,
// still HTTP 200), not a 404 -- handleReload's own domain-required check
// only rejects an EMPTY domain (see TestHandler_ReloadRoute_EmptyDomain_Returns400);
// anything else, known or not, is dispatched to the coordinator.
func TestHandler_ReloadRoute_UnknownDomain_ReturnsOKFalseNot404(t *testing.T) {
	coordinator := &reload.ReloadCoordinator{Reloaders: map[string]func() error{}, OnAudit: func(reload.ReloadResult) {}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, coordinator, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/nonsense", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the coordinator, not the HTTP layer, reports unknown-domain failure); body=%s", rec.Code, rec.Body.String())
	}
	var got reload.ReloadResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.OK {
		t.Errorf("expected OK=false for an unknown domain, got %+v", got)
	}
}

// --- Task 6: GET /dashboard/api/reload/history ---

type fakeReloadHistorySource struct {
	entries []reload.ReloadEvent
}

func (f *fakeReloadHistorySource) Since(afterID int64, limit int) []reload.ReloadEvent {
	var out []reload.ReloadEvent
	for _, e := range f.entries {
		if e.ID <= afterID {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func TestHandler_HandleReloadHistory_ReturnsBufferedEntriesAsJSON(t *testing.T) {
	history := &fakeReloadHistorySource{entries: []reload.ReloadEvent{
		{ID: 1, ReloadResult: reload.ReloadResult{
			Domain:    "policy",
			OK:        false,
			Error:     "unknown domain",
			AppliedBy: "alice",
			Timestamp: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC),
		}},
	}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, history, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/reload/history", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []domain.ReloadEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "policy" || got[0].OK || got[0].Error != "unknown domain" || got[0].AppliedBy != "alice" {
		t.Errorf("unexpected decoded response: %+v", got)
	}
}

// TestHandler_HandleReloadHistory_TakesPrecedenceOverReloadPrefixRoute
// proves the exact "/dashboard/api/reload/history" registration wins over
// "/dashboard/api/reload/"'s subtree match (handleReload) for this one
// literal path -- ServeMux always prefers the more specific pattern, so
// GET /dashboard/api/reload/history must never be treated as a reload of
// a domain literally named "history".
func TestHandler_HandleReloadHistory_TakesPrecedenceOverReloadPrefixRoute(t *testing.T) {
	coordinator := &reload.ReloadCoordinator{
		Reloaders: map[string]func() error{"history": func() error { panic("must not be dispatched to the reload coordinator") }},
		OnAudit:   func(reload.ReloadResult) {},
	}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, coordinator, allowReloadAuthorizer{identity: "alice"}, &fakeReloadHistorySource{}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/reload/history", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandler_HandleReloadHistory_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/reload/history", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when reload history is not wired, got %d", rec.Code)
	}
}

func TestHandler_HandleReloadHistory_NonGetMethod_Returns405(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, &fakeReloadHistorySource{}, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/history", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for non-GET method, got %d", rec.Code)
	}
}

var errPolicyWriteFailed = errors.New("refusing to write invalid policy: rule 0: identity must not be empty")
var errBudgetWriteFailed = errors.New("refusing to write invalid config: budget.requests_per_window must be > 0")

// policyWritePayload is the exact PUT /dashboard/api/policy JSON shape
// handlePolicyWrite decodes -- kept as a small helper so every test
// below builds a request body the same way.
func policyWritePayload(t *testing.T, rules []map[string]string, def string) *bytes.Reader {
	t.Helper()
	body := map[string]any{"rules": rules, "default": def}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(data)
}

// TestHandler_PolicyWriteRoute_MethodFieldReachesWriteAndReload proves the
// Rule editor's Method column (resources/read, prompts/get, etc.) isn't
// silently dropped between the wire request and WriteAndReload -- the
// widening feature's dashboard write-path proof. See
// docs/superpowers/specs/2026-08-08-widen-policy-resources-prompts-design.md.
func TestHandler_PolicyWriteRoute_MethodFieldReachesWriteAndReload(t *testing.T) {
	writer := &fakePolicyWriter{}
	updated := domain.PolicyInfo{Backend: "yaml"}
	h := adapter.NewHandler(nil, nil, updated, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, writer, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", policyWritePayload(t,
		[]map[string]string{{"identity": "alice", "method": "resources/read", "tool": "file:///data/report.csv", "effect": "allow"}}, "deny"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(writer.lastRules) != 1 || writer.lastRules[0].Method != "resources/read" {
		t.Errorf("expected the decoded rule's Method to reach WriteAndReload unchanged, got %+v", writer.lastRules)
	}
}

func TestHandler_PolicyWriteRoute_GetStillReturnsPolicyInfo(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{Backend: "yaml", Source: "rules: []\ndefault: allow\n"}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got domain.PolicyInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Backend != "yaml" {
		t.Errorf("expected Backend = %q, got %q", "yaml", got.Backend)
	}
}

func TestHandler_PolicyWriteRoute_NilWriterOrAuth_Returns404(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", policyWritePayload(t, nil, "allow"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when policyWriter/reloadAuth are not wired, got %d", rec.Code)
	}
}

func TestHandler_PolicyWriteRoute_AuthorizerDenies_Returns403(t *testing.T) {
	writer := &fakePolicyWriter{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, denyReloadAuthorizer{}, nil, nil, writer, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", policyWritePayload(t, nil, "allow"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 when ReloadAuthorizer denies, got %d", rec.Code)
	}
	if writer.lastAppliedBy != "" {
		t.Error("expected WriteAndReload to never be called when the authorizer denies")
	}
}

// TestHandler_PolicyWriteRoute_Success_AppliedByFromAuthorizer proves
// appliedBy comes from ReloadAuthorizer.Authorize's resolved identity,
// never from the request body -- mirrors
// TestHandler_ReloadRoute_Success_ReturnsResultWithAppliedByFromAuthorizer's
// exact claim for the reload endpoint.
func TestHandler_PolicyWriteRoute_Success_AppliedByFromAuthorizer(t *testing.T) {
	writer := &fakePolicyWriter{}
	updated := domain.PolicyInfo{Backend: "yaml", Source: "rules:\n  - identity: alice\n    tool: search\n    effect: allow\ndefault: deny\n"}
	h := adapter.NewHandler(nil, nil, updated, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, writer, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", policyWritePayload(t,
		[]map[string]string{{"identity": "alice", "tool": "search", "effect": "allow"}}, "deny"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if writer.lastAppliedBy != "alice" {
		t.Errorf("expected appliedBy = %q (from the authorizer), got %q", "alice", writer.lastAppliedBy)
	}
	if len(writer.lastRules) != 1 || writer.lastRules[0].Identity != "alice" || writer.lastRules[0].Tool != "search" || writer.lastRules[0].Effect != policydomain.EffectAllow {
		t.Errorf("expected the decoded rule to reach WriteAndReload unchanged, got %+v", writer.lastRules)
	}
	if writer.lastDefault != policydomain.EffectDeny {
		t.Errorf("expected default = deny, got %q", writer.lastDefault)
	}
	var got domain.PolicyInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Source != updated.Source {
		t.Error("expected the response body to reflect the post-write policy.Current(), proving the caller doesn't need a second GET")
	}
}

func TestHandler_PolicyWriteRoute_WriterError_Returns400WithMessage(t *testing.T) {
	writer := &fakePolicyWriter{err: errPolicyWriteFailed}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, writer, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", policyWritePayload(t, nil, "allow"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var got struct{ Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Error != errPolicyWriteFailed.Error() {
		t.Errorf("expected the write error surfaced verbatim, got %q", got.Error)
	}
}

func TestHandler_PolicyWriteRoute_MalformedBody_Returns400(t *testing.T) {
	writer := &fakePolicyWriter{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, writer, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for a malformed body, got %d", rec.Code)
	}
	if writer.lastAppliedBy != "" {
		t.Error("expected WriteAndReload to never be called for a malformed body")
	}
}

func TestHandler_PolicyRoute_UnsupportedMethod_Returns405(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for DELETE, got %d", rec.Code)
	}
}

func budgetWritePayload(t *testing.T, requestsPerWindow, windowSeconds int, tenantOverrides []map[string]any) *bytes.Reader {
	t.Helper()
	body := map[string]any{
		"default":          map[string]any{"requests_per_window": requestsPerWindow, "window_seconds": windowSeconds},
		"tenant_overrides": tenantOverrides,
		"tool_overrides":   []map[string]any{},
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(data)
}

func TestHandler_BudgetWriteRoute_GetStillReturnsBudget(t *testing.T) {
	src := &fakeBudgetSource{defaultLimit: budgetdomain.LimitInfo{RequestsPerWindow: 25, Window: 60 * time.Second}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, src, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/budget", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandler_BudgetWriteRoute_NilWriterOrAuth_Returns404(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/budget", budgetWritePayload(t, 25, 60, nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when budgetWriter/reloadAuth are not wired, got %d", rec.Code)
	}
}

func TestHandler_BudgetWriteRoute_AuthorizerDenies_Returns403(t *testing.T) {
	writer := &fakeBudgetWriter{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, denyReloadAuthorizer{}, nil, nil, nil, writer, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/budget", budgetWritePayload(t, 25, 60, nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 when ReloadAuthorizer denies, got %d", rec.Code)
	}
	if writer.lastAppliedBy != "" {
		t.Error("expected WriteAndReload to never be called when the authorizer denies")
	}
}

// TestHandler_BudgetWriteRoute_Success_AppliedByFromAuthorizer mirrors
// TestHandler_PolicyWriteRoute_Success_AppliedByFromAuthorizer exactly,
// for the Budget editor's own write path.
func TestHandler_BudgetWriteRoute_Success_AppliedByFromAuthorizer(t *testing.T) {
	writer := &fakeBudgetWriter{}
	src := &fakeBudgetSource{defaultLimit: budgetdomain.LimitInfo{RequestsPerWindow: 25, Window: 60 * time.Second}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, src, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, writer, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/budget", budgetWritePayload(t, 10, 30,
		[]map[string]any{{"scope": "tenant", "name": "acme", "requests_per_window": 5, "window_seconds": 60}}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if writer.lastAppliedBy != "alice" {
		t.Errorf("expected appliedBy = %q (from the authorizer), got %q", "alice", writer.lastAppliedBy)
	}
	if writer.lastDefault.RequestsPerWindow != 10 || writer.lastDefault.Window != 30*time.Second {
		t.Errorf("expected the decoded default limit to reach WriteAndReload unchanged, got %+v", writer.lastDefault)
	}
	if len(writer.lastTenantOverrides) != 1 || writer.lastTenantOverrides[0].Name != "acme" {
		t.Errorf("expected the decoded tenant override to reach WriteAndReload unchanged, got %+v", writer.lastTenantOverrides)
	}
}

func TestHandler_BudgetWriteRoute_WriterError_Returns400WithMessage(t *testing.T) {
	writer := &fakeBudgetWriter{err: errBudgetWriteFailed}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, writer, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/budget", budgetWritePayload(t, 25, 60, nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var got struct{ Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Error != errBudgetWriteFailed.Error() {
		t.Errorf("expected the write error surfaced verbatim, got %q", got.Error)
	}
}

func TestHandler_BudgetWriteRoute_MalformedBody_Returns400(t *testing.T) {
	writer := &fakeBudgetWriter{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "alice"}, nil, nil, nil, writer, nil, nil)

	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/budget", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for a malformed body, got %d", rec.Code)
	}
	if writer.lastAppliedBy != "" {
		t.Error("expected WriteAndReload to never be called for a malformed body")
	}
}

func TestHandler_BudgetRoute_UnsupportedMethod_Returns405(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/budget", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for DELETE, got %d", rec.Code)
	}
}

type fakeComplianceSource struct {
	manifest compliancedomain.Manifest
	err      error
	gotFrom  time.Time
	gotTo    time.Time
}

func (f *fakeComplianceSource) Query(ctx context.Context, from, to time.Time) (compliancedomain.Manifest, error) {
	f.gotFrom, f.gotTo = from, to
	return f.manifest, f.err
}

func TestHandler_HandleCompliance_ReturnsManifestAsJSON(t *testing.T) {
	src := &fakeComplianceSource{manifest: compliancedomain.Manifest{
		WardlineVersion: "0.6.0", AuditEntryCount: 5,
		AuditDecisionCounts: map[string]int{"allow": 3, "deny": 2},
	}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, src, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/compliance?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got compliancedomain.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got.AuditEntryCount != 5 || got.AuditDecisionCounts["allow"] != 3 {
		t.Errorf("unexpected manifest: %+v", got)
	}
	wantFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if !src.gotFrom.Equal(wantFrom) || !src.gotTo.Equal(wantTo) {
		t.Errorf("expected Query to receive the parsed from/to, got from=%v to=%v", src.gotFrom, src.gotTo)
	}
}

func TestHandler_HandleCompliance_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/compliance?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404 when compliance source is not wired, got %d", rec.Code)
	}
}

func TestHandler_HandleCompliance_MissingFromOrTo_Returns400(t *testing.T) {
	src := &fakeComplianceSource{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, src, nil)

	for _, query := range []string{"", "?from=2026-01-01T00:00:00Z", "?to=2026-02-01T00:00:00Z"} {
		req := httptest.NewRequest(http.MethodGet, "/dashboard/api/compliance"+query, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: want 400, got %d", query, rec.Code)
		}
	}
}

func TestHandler_HandleCompliance_InvalidTimestamp_Returns400(t *testing.T) {
	src := &fakeComplianceSource{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, src, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/compliance?from=not-a-date&to=2026-02-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for an unparsable from, got %d", rec.Code)
	}
}

func TestHandler_HandleCompliance_FromAfterTo_Returns400(t *testing.T) {
	src := &fakeComplianceSource{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, src, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/compliance?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 when from is after to, got %d", rec.Code)
	}
}

func TestHandler_HandleCompliance_QueryError_Returns500(t *testing.T) {
	src := &fakeComplianceSource{err: errors.New("postgres unreachable")}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, src, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/compliance?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500 when Query fails, got %d", rec.Code)
	}
}

func TestHandler_HandleCompliance_UnsupportedMethod_Returns405(t *testing.T) {
	src := &fakeComplianceSource{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, src, nil)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/compliance?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for POST, got %d", rec.Code)
	}
}

// --- Task 10: dashboard Approvals view ---

// fakeApprovalSource is a settable stub for adapter.ApprovalSource -- returns
// fixed pending requests and records the last decision it was called with,
// matching this file's fake-with-a-spy pattern. decideErr lets a test drive
// the 404-vs-204 branch (unknown/already-decided id).
type fakeApprovalSource struct {
	pending       []approvaldomain.Request
	decideErr     error
	lastApproveID string
	lastApproveBy string
	lastDenyID    string
	lastDenyBy    string
}

func (f *fakeApprovalSource) ListPending(tenant string) []approvaldomain.Request { return f.pending }

func (f *fakeApprovalSource) Approve(id, by string) error {
	f.lastApproveID, f.lastApproveBy = id, by
	return f.decideErr
}

func (f *fakeApprovalSource) Deny(id, by string) error {
	f.lastDenyID, f.lastDenyBy = id, by
	return f.decideErr
}

func TestHandler_HandleApprovals_NilSourceReturns404(t *testing.T) {
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/approvals", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when approvals is not wired (feature off), got %d", rec.Code)
	}
}

func TestHandler_HandleApprovals_ReturnsPendingAsJSON(t *testing.T) {
	appr := &fakeApprovalSource{pending: []approvaldomain.Request{
		{ID: "req-1", Identity: "alice", Tenant: "acme", Tool: "write_file", Method: "tools/call", Params: map[string]string{"path": "/etc/passwd"}, Status: approvaldomain.StatusPending},
	}}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, appr)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/approvals", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got []approvaldomain.Request
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(got) != 1 || got[0].ID != "req-1" || got[0].Identity != "alice" || got[0].Tool != "write_file" {
		t.Errorf("unexpected decoded response: %+v", got)
	}
}

func TestHandler_HandleApprovalDecision_DenyingAuthorizerReturns403(t *testing.T) {
	appr := &fakeApprovalSource{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, denyReloadAuthorizer{}, nil, nil, nil, nil, nil, appr)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/approvals/req-1/approve", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 when config-edit authorizer denies, got %d", rec.Code)
	}
	if appr.lastApproveID != "" {
		t.Errorf("source must not be called when authorizer denies, got approve of %q", appr.lastApproveID)
	}
}

func TestHandler_HandleApprovalDecision_AllowingReturns204AndCallsSource(t *testing.T) {
	appr := &fakeApprovalSource{}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "op@acme"}, nil, nil, nil, nil, nil, appr)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/approvals/req-1/approve", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d; body=%s", rec.Code, rec.Body.String())
	}
	if appr.lastApproveID != "req-1" || appr.lastApproveBy != "op@acme" {
		t.Errorf("Approve called with (%q, %q), want (req-1, op@acme) -- appliedBy must come from the authorizer, not the client", appr.lastApproveID, appr.lastApproveBy)
	}
}

func TestHandler_HandleApprovalDecision_UnknownIDReturns404(t *testing.T) {
	appr := &fakeApprovalSource{decideErr: errors.New("unknown or already-decided")}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil, nil, nil, nil, allowReloadAuthorizer{identity: "op@acme"}, nil, nil, nil, nil, nil, appr)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/approvals/nope/deny", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown/already-decided id, got %d", rec.Code)
	}
	if appr.lastDenyID != "nope" {
		t.Errorf("Deny should still be attempted (got id %q), the 404 comes from its error", appr.lastDenyID)
	}
}
