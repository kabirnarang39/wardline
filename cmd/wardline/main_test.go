package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	rbacusecase "github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
)

// TestBuildTopHandler_EmptyMap_ProxyHandlesEverythingUnchanged exercises
// buildTopHandler's genuinely-empty-map fast path directly -- runServe
// itself never actually calls buildTopHandler with an empty map (health
// routes are always registered), but the fast path is retained as a
// real, useful contract of the function on its own: called with no
// extra routes at all, it must return the bare proxy handler completely
// unchanged, not wrap it in a mux.
func TestBuildTopHandler_EmptyMap_ProxyHandlesEverythingUnchanged(t *testing.T) {
	proxyHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{})
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !proxyHit {
		t.Error("expected the proxy handler to receive every request when extraRoutes is empty")
	}
}

// TestBuildTopHandler_WebUIOff_DashboardPathGoesToProxy reflects what a
// real "no optional features" deployment actually looks like since the
// HA-deployment cycle: extraRoutes is never truly empty, because
// /healthz and /readyz are always registered regardless of any feature
// flag. /dashboard/ (unregistered here, web_ui off) must still reach the
// proxy through the mux path, exactly as it did under the old
// genuinely-empty-map fast path.
func TestBuildTopHandler_WebUIOff_DashboardPathGoesToProxy(t *testing.T) {
	proxyHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("health handler should not be reached for /dashboard/")
	})

	h := buildTopHandler(proxy, map[string]http.Handler{
		"/healthz": healthHandler,
		"/readyz":  healthHandler,
	})
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !proxyHit {
		t.Error("expected the proxy handler to receive /dashboard/ requests when web_ui is off")
	}
}

func TestBuildTopHandler_WebUIOn_DashboardPathGoesToDashboard(t *testing.T) {
	dashboardHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("proxy handler should not be reached for /dashboard/ when web_ui is on")
	})
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dashboardHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{"/dashboard/": dashboard})
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !dashboardHit {
		t.Error("expected the dashboard handler to receive /dashboard/ requests when web_ui is on")
	}
}

func TestBuildTopHandler_WebUIOn_OtherPathsStillGoToProxy(t *testing.T) {
	proxyHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("dashboard handler should not be reached for non-dashboard paths")
	})

	h := buildTopHandler(proxy, map[string]http.Handler{"/dashboard/": dashboard})
	req := httptest.NewRequest(http.MethodGet, "/some/mcp/tool", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !proxyHit {
		t.Error("expected the proxy handler to receive non-/dashboard/ requests")
	}
}

func TestBuildTopHandler_WebUIAndCredentialIssuanceOn_AllRoutesReachCorrectHandler(t *testing.T) {
	proxyHit := false
	dashboardHit := false
	tokenHit := false
	revokeHit := false

	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dashboardHit = true })
	token := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { tokenHit = true })
	revoke := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { revokeHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{
		"/dashboard/":         dashboard,
		"/credentials/token":  token,
		"/credentials/revoke": revoke,
	})

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/dashboard/", nil))
	if !dashboardHit {
		t.Error("expected the dashboard handler to receive /dashboard/ requests")
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/token", nil))
	if !tokenHit {
		t.Error("expected the token handler to receive /credentials/token requests")
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil))
	if !revokeHit {
		t.Error("expected the revoke handler to receive /credentials/revoke requests")
	}

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/some/mcp/tool", nil))
	if !proxyHit {
		t.Error("expected the proxy handler to receive requests for every other path")
	}
}

// fakeRevokeIdentityAuth is a minimal proxyadapter.IdentityAuthenticator
// fake for newRevokeAuthorizer's tests.
type fakeRevokeIdentityAuth struct {
	identity string
	err      error
}

func (f fakeRevokeIdentityAuth) Authenticate(r *http.Request) (string, error) {
	return f.identity, f.err
}

// stubAuthorizer is a domain.Authorizer fake whose verdict is fixed.
type stubAuthorizer struct {
	verdict bool
}

func (s stubAuthorizer) Authorize(identity, tenant string, perm rbacdomain.Permission) bool {
	return s.verdict
}

// panicIfCalledAuthorizer proves newRevokeAuthorizer never reaches
// checker.Check (and thus never reaches the underlying domain.Authorizer)
// when identity resolution fails.
type panicIfCalledAuthorizer struct{}

func (panicIfCalledAuthorizer) Authorize(identity, tenant string, perm rbacdomain.Permission) bool {
	panic("authorizer must not be called when identity resolution fails")
}

// alwaysOnFlags is a flags.Provider stub that reports every flag enabled,
// so rbacusecase.Checker always delegates to the authorizer under test.
type alwaysOnFlags struct{}

func (alwaysOnFlags) Enabled(name string) bool { return true }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewRevokeAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "alice"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true})

	authz := newRevokeAuthorizer(&identityAuth, checker, testLogger())
	if !authz.Allowed(httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil)) {
		t.Error("expected Allowed to return true when identity resolves and the checker grants")
	}
}

func TestNewRevokeAuthorizer_DeniesWhenCheckerDenies(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: false})

	authz := newRevokeAuthorizer(&identityAuth, checker, testLogger())
	if authz.Allowed(httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil)) {
		t.Error("expected Allowed to return false when the checker denies")
	}
}

func TestNewRevokeAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{err: errors.New("no identity")}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, panicIfCalledAuthorizer{})

	authz := newRevokeAuthorizer(&identityAuth, checker, testLogger())
	if authz.Allowed(httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil)) {
		t.Error("expected Allowed to return false when identity resolution fails")
	}
}

// TestRunExportEvidence_NoFeaturesBlock_ManifestFeaturesIsEmptyMapNotNull
// covers a real operator-facing bug: a wardline.yaml with no top-level
// features: key decodes cfg.Features as a nil map (yaml.v3's behavior for
// an absent mapping key), and BuildManifest passes that map straight
// through with no nil-guard (unlike AuditDecisionCounts/AnomalyKindCounts,
// which it always initializes via make()). Without runExportEvidence
// substituting an empty map for nil, the exported manifest.json would
// contain "features": null instead of "features": {}.
func TestRunExportEvidence_NoFeaturesBlock_ManifestFeaturesIsEmptyMapNotNull(t *testing.T) {
	dir := t.TempDir()

	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(auditPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Deliberately no "features:" key at all.
	configPath := filepath.Join(dir, "wardline.yaml")
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(dir, "evidence.tar.gz")
	runExportEvidence(testLogger(), []string{
		"-config", configPath,
		"-from", "2020-01-01T00:00:00Z",
		"-to", "2030-01-01T00:00:00Z",
		"-output", outputPath,
	})

	manifestJSON := readBundleFile(t, outputPath, "manifest.json")
	var manifest struct {
		Features map[string]bool `json:"features"`
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatalf("unmarshal manifest.json: %v", err)
	}
	if manifest.Features == nil {
		t.Error("expected manifest.json's features to unmarshal as {} (empty map), got null")
	}
	if !bytes.Contains(manifestJSON, []byte(`"features": {}`)) {
		t.Errorf("expected manifest.json to contain literal \"features\": {}, got:\n%s", manifestJSON)
	}
}

// TestRunExportEvidence_MissingAnomalyFileIsZeroAnomaliesAndBundleIsOwnerOnly
// covers two seams between the CLI wiring and the stores it reads:
//
//  1. anomaly.output only exists once serve has run with
//     anomaly_detection on (buildAnomalyWriter's O_CREATE). An operator
//     who flips the flag on and exports before restarting must get an
//     empty-anomaly bundle, not "open anomaly file: no such file".
//  2. The bundle aggregates the 0600 audit trail, the rbac bindings and
//     the policy source into one artifact, so it must not land
//     world-readable via os.Create's 0666&umask default.
func TestRunExportEvidence_MissingAnomalyFileIsZeroAnomaliesAndBundleIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()

	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(auditPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Deliberately never created.
	anomalyPath := filepath.Join(dir, "anomaly.jsonl")

	configPath := filepath.Join(dir, "wardline.yaml")
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"features:\n  anomaly_detection: true\n" +
		"anomaly:\n  output: \"" + anomalyPath + "\"\n  window_seconds: 60\n" +
		"audit:\n  output: \"" + auditPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(dir, "evidence.tar.gz")
	runExportEvidence(testLogger(), []string{
		"-config", configPath,
		"-from", "2020-01-01T00:00:00Z",
		"-to", "2030-01-01T00:00:00Z",
		"-output", outputPath,
	})

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("expected a bundle to be written despite the missing anomaly file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected the evidence bundle to be owner-only (0600), got %04o", perm)
	}

	manifestJSON := readBundleFile(t, outputPath, "manifest.json")
	var manifest struct {
		AnomalyEntryCount int `json:"anomaly_entry_count"`
	}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatalf("unmarshal manifest.json: %v", err)
	}
	if manifest.AnomalyEntryCount != 0 {
		t.Errorf("expected 0 anomalies, got %d", manifest.AnomalyEntryCount)
	}
	if !bytes.Contains(manifestJSON, []byte(`"unparsable_anomaly_lines_skipped": 0`)) {
		t.Errorf("expected the anomaly skip counter in manifest.json, got:\n%s", manifestJSON)
	}
}

// readBundleFile extracts one named file's contents from a gzip+tar
// evidence bundle written by complianceadapter.WriteBundle.
func readBundleFile(t *testing.T, bundlePath, name string) []byte {
	t.Helper()
	f, err := os.Open(bundlePath)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("bundle has no file named %q", name)
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if hdr.Name != name {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %q from bundle: %v", name, err)
		}
		return data
	}
}
