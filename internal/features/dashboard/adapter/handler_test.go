package adapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	federationdomain "github.com/kabirnarang39/wardline/internal/features/federation/domain"
	federationusecase "github.com/kabirnarang39/wardline/internal/features/federation/usecase"
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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, policy, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{status: status}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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

func TestHandler_ServesKnownStaticAsset(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

	for _, path := range []string{"/dashboard/api/audit", "/dashboard/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
			t.Errorf("%s: Content-Security-Policy = %q, want \"default-src 'self'\"", path, got)
		}
	}
}

func TestHandler_RootServesIndexHTML(t *testing.T) {
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/anomalies", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when anomalies is not wired (feature off), got %d", rec.Code)
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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, federation, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, nil, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, fakeTenantScopeResolver{tenant: "acme"}, nil)

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, fakeTenantScopeResolver{tenant: ""}, nil)

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, nil, nil)

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), anomalies, nil, blocked, fakeTenantScopeResolver{tenant: "acme"}, nil)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, federation, nil, fakeTenantScopeResolver{tenant: "acme"}, nil)

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
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, denyAllUnblockAuthorizer{})

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
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{})

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
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{})

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
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{})

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
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, authz)

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets(), nil, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when blocked/unblock are not wired (feature off or rbac off), got %d", rec.Code)
	}
}

func TestHandler_UnblockRoute_NonDeleteMethod_Returns405(t *testing.T) {
	blocked := &fakeBlockedSource{unblockResult: true}
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, nil, allowAllUnblockAuthorizer{})

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
	h := adapter.NewHandler(nil, nil, domain.PolicyInfo{}, testAssets(), nil, nil, blocked, scope, allowAllUnblockAuthorizer{})

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
