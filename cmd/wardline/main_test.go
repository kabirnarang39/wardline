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
	"strings"
	"testing"

	complianceadapter "github.com/kabirnarang39/wardline/internal/features/compliance/adapter"
	compliancedomain "github.com/kabirnarang39/wardline/internal/features/compliance/domain"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	proxydomain "github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	proxyusecase "github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
	rbacadapter "github.com/kabirnarang39/wardline/internal/features/rbac/adapter"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	rbacusecase "github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
	scimusecase "github.com/kabirnarang39/wardline/internal/features/scim/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
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

// TestBuildTopHandler_FaviconRouteWinsOverProxyCatchAll guards the actual
// bug this route exists to fix: browsers auto-request GET /favicon.ico on
// every page load, and without a more-specific mux entry it used to fall
// through to the "/" catch-all proxy handler, which audited it as a
// malformed JSON-RPC "error" -- a stray reading on a dashboard that has
// seen zero real traffic. Mirrors TestBuildTopHandler_WebUIOn_OtherPathsStillGoToProxy's
// shape exactly, just for /favicon.ico instead of /dashboard/.
func TestBuildTopHandler_FaviconRouteWinsOverProxyCatchAll(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("proxy handler should not be reached for /favicon.ico when the route is registered")
	})
	faviconHit := false
	favicon := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { faviconHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{"/favicon.ico": favicon})
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if !faviconHit {
		t.Error("expected the favicon handler to receive /favicon.ico requests, not the proxy catch-all")
	}
}

// TestFaviconHandler_ServesEmbeddedIconWithImageContentType exercises the
// real handler (not a stub), proving it serves actual, non-empty bytes
// read from the dashboard's embedded web/dist/favicon.svg with an
// explicit SVG content type -- the same mark the docs site and landing
// page use, and not relying on the host's mime.types having an entry.
func TestFaviconHandler_ServesEmbeddedIconWithImageContentType(t *testing.T) {
	h := faviconHandler(testLogger())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("expected Content-Type image/svg+xml, got %q", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("expected a non-empty favicon body")
	}
	// A cheap sanity check that this is the real SVG mark, not a
	// placeholder blob.
	if body := rec.Body.String(); !strings.Contains(body, "<svg") {
		t.Errorf("expected an SVG body containing \"<svg\", got %q", body[:min(32, len(body))])
	}
}

// --- I1/I4 fix-wave regression tests --------------------------------------
//
// I1: the "unregistered path falls through to the proxy, gets audited as a
// spurious error" bug class (first found/fixed for /favicon.ico, then
// /credentials/*) recurs at generic browser/crawler noise paths and at the
// /federation/summaries and /scim/v2/* feature-gated paths. I4: the
// /credentials/* fix (8ffb3bf) shipped with zero tests -- these also cover
// that gap.

// TestRouteOrNotFound_DisabledReturnsCleanNotFound guards routeOrNotFound's
// disabled branch directly: the wrapped handler must never be invoked, and
// the response must be a plain 404, not a JSON-RPC-shaped error.
func TestRouteOrNotFound_DisabledReturnsCleanNotFound(t *testing.T) {
	h := routeOrNotFound(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("real handler should not be invoked when disabled")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/whatever", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "jsonrpc") {
		t.Errorf("expected a plain 404 body, got %q", rec.Body.String())
	}
}

// TestRouteOrNotFound_EnabledPassesThroughUnchanged guards the enabled
// branch: the real handler must run, completely unchanged.
func TestRouteOrNotFound_EnabledPassesThroughUnchanged(t *testing.T) {
	hit := false
	h := routeOrNotFound(true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/whatever", nil))
	if !hit {
		t.Error("expected the real handler to be invoked when enabled")
	}
}

// TestBuildTopHandler_NoiseRoutesWinOverProxyCatchAll guards I1's fix for
// generic browser/crawler noise paths: none of robots.txt, the two
// apple-touch-icon variants, the Chrome DevTools well-known probe, or
// sitemap.xml are ever a legitimate MCP JSON-RPC call, so each must be
// answered by its own route rather than falling through to the "/"
// catch-all proxy handler and getting audited as a spurious error --
// mirrors TestBuildTopHandler_FaviconRouteWinsOverProxyCatchAll's shape.
func TestBuildTopHandler_NoiseRoutesWinOverProxyCatchAll(t *testing.T) {
	noisePaths := []string{
		"/robots.txt",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
		"/.well-known/appspecific/com.chrome.devtools.json",
		"/sitemap.xml",
	}
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("proxy handler should not be reached for %s", r.URL.Path)
	})
	routes := map[string]http.Handler{}
	for _, p := range noisePaths {
		routes[p] = http.HandlerFunc(noiseRouteHandler)
	}
	h := buildTopHandler(proxy, routes)
	for _, p := range noisePaths {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", p, rec.Code)
		}
	}
}

// TestBuildTopHandler_FederationAndSCIMRoutesOffReturn404NotProxy guards
// I1's fix for the two feature-gated instances of this bug class:
// /federation/summaries and /scim/v2/* previously fell through to the
// proxy catch-all -- and got audited as spurious errors -- whenever their
// owning flag was off. Mirrors the /credentials/* disabled-state test
// below.
func TestBuildTopHandler_FederationAndSCIMRoutesOffReturn404NotProxy(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("proxy handler should not be reached for %s when its flag is off", r.URL.Path)
	})
	realHandlerHit := false
	realHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { realHandlerHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{
		"/federation/summaries": routeOrNotFound(false, realHandler),
		"/scim/v2/":             routeOrNotFound(false, realHandler),
	})

	for _, p := range []string{"/federation/summaries", "/scim/v2/Users"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", p, rec.Code)
		}
	}
	if realHandlerHit {
		t.Error("expected the real federation/scim handler not to be invoked while disabled")
	}
}

// TestBuildTopHandler_FederationAndSCIMRoutesOnReachRealHandler confirms
// the enabled path's existing behavior is unchanged by I1's fix.
func TestBuildTopHandler_FederationAndSCIMRoutesOnReachRealHandler(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("proxy handler should not be reached when federation/scim are enabled")
	})
	federationHit, scimHit := false, false
	federation := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { federationHit = true })
	scim := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { scimHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{
		"/federation/summaries": routeOrNotFound(true, federation),
		"/scim/v2/":             routeOrNotFound(true, scim),
	})

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/federation/summaries", nil))
	if !federationHit {
		t.Error("expected the federation handler to receive /federation/summaries requests when enabled")
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil))
	if !scimHit {
		t.Error("expected the scim handler to receive /scim/v2/* requests when enabled")
	}
}

// TestCredentialsRoutes_DisabledReturnCleanNotFound is I4: the
// /credentials/* fix (8ffb3bf) shipped with no test that the disabled-state
// 404 actually fires. Confirms all three routes return a clean 404 -- not
// a JSON-RPC-shaped proxy error, not the real handler -- when
// credential_issuance is off.
func TestCredentialsRoutes_DisabledReturnCleanNotFound(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("proxy handler should not be reached for %s when credential_issuance is off", r.URL.Path)
	})
	realHandlerHit := false
	real := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { realHandlerHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{
		"/credentials/token":   http.HandlerFunc(credentialsRouteOrNotFound(false, real.ServeHTTP)),
		"/credentials/revoke":  http.HandlerFunc(credentialsRouteOrNotFound(false, real.ServeHTTP)),
		"/credentials/refresh": http.HandlerFunc(credentialsRouteOrNotFound(false, real.ServeHTTP)),
	})

	for _, p := range []string{"/credentials/token", "/credentials/revoke", "/credentials/refresh"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", p, rec.Code)
		}
		if body := rec.Body.String(); strings.Contains(body, "jsonrpc") {
			t.Errorf("%s: expected a plain 404 body, not a JSON-RPC-shaped error, got %q", p, body)
		}
	}
	if realHandlerHit {
		t.Error("expected the real credential handler not to be invoked while credential_issuance is off")
	}
}

// TestCredentialsRoutes_EnabledReachRealHandler is I4's routing-layer smoke
// check for the enabled path -- deeper token/revoke/refresh semantics are
// already covered elsewhere (e2e_test.go, e2e_tenant_isolation_test.go);
// this test's job is confirming the routing layer only.
func TestCredentialsRoutes_EnabledReachRealHandler(t *testing.T) {
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("proxy handler should not be reached when credential_issuance is on")
	})
	var tokenHit, revokeHit, refreshHit bool
	token := func(w http.ResponseWriter, r *http.Request) { tokenHit = true }
	revoke := func(w http.ResponseWriter, r *http.Request) { revokeHit = true }
	refresh := func(w http.ResponseWriter, r *http.Request) { refreshHit = true }

	h := buildTopHandler(proxy, map[string]http.Handler{
		"/credentials/token":   http.HandlerFunc(credentialsRouteOrNotFound(true, token)),
		"/credentials/revoke":  http.HandlerFunc(credentialsRouteOrNotFound(true, revoke)),
		"/credentials/refresh": http.HandlerFunc(credentialsRouteOrNotFound(true, refresh)),
	})

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/token", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/refresh", nil))

	if !tokenHit || !revokeHit || !refreshHit {
		t.Errorf("expected all three credential handlers to be invoked when enabled: token=%v revoke=%v refresh=%v", tokenHit, revokeHit, refreshHit)
	}
}

// TestCredentialsRoutes_WinOverProxyCatchAll_MapIterationOrder is I4's
// catch-all-precedence guard, mirroring
// TestBuildTopHandler_FaviconRouteWinsOverProxyCatchAll -- run repeatedly
// since Go deliberately randomizes map iteration order and buildTopHandler
// ranges over extraRoutes to register each pattern on the mux.
// http.ServeMux's own longest-match routing (not registration order) is
// what actually guarantees /credentials/* always beats "/", but this
// codifies that guarantee as a real test instead of the final reviewer's
// manual 5x spot-check of the real binary.
func TestCredentialsRoutes_WinOverProxyCatchAll_MapIterationOrder(t *testing.T) {
	paths := []string{"/credentials/token", "/credentials/revoke", "/credentials/refresh"}
	for i := 0; i < 20; i++ {
		proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("proxy handler should not be reached for %s", r.URL.Path)
		})
		hit := map[string]bool{}
		routes := map[string]http.Handler{}
		for _, p := range paths {
			p := p
			routes[p] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit[p] = true })
		}
		h := buildTopHandler(proxy, routes)
		for _, p := range paths {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, p, nil))
		}
		for _, p := range paths {
			if !hit[p] {
				t.Errorf("iteration %d: expected %s to reach its own handler, not the proxy", i, p)
			}
		}
	}
}

// fakeRevokeIdentityAuth is a minimal proxyadapter.IdentityAuthenticator
// fake for newRevokeAuthorizer's tests.
type fakeRevokeIdentityAuth struct {
	identity string
	tenant   string
	err      error
}

func (f fakeRevokeIdentityAuth) Authenticate(r *http.Request) (string, string, error) {
	return f.identity, f.tenant, f.err
}

// stubAuthorizer is a domain.Authorizer fake whose verdicts are fixed.
// verdict controls Authorize (the plain permission check); global
// controls IsGlobal (ClusterRoleBinding vs. tenant-scoped RoleBinding) --
// kept independent since newRevokeAuthorizer's cross-tenant check only
// engages once Authorize already granted.
type stubAuthorizer struct {
	verdict bool
	global  bool
}

func (s stubAuthorizer) Authorize(identity, tenant string, perm rbacdomain.Permission) bool {
	return s.verdict
}

func (s stubAuthorizer) IsGlobal(identity string, perm rbacdomain.Permission) bool {
	return s.global
}

// panicIfCalledAuthorizer proves newRevokeAuthorizer never reaches
// checker.Check (and thus never reaches the underlying domain.Authorizer)
// when identity resolution fails.
type panicIfCalledAuthorizer struct{}

func (panicIfCalledAuthorizer) Authorize(identity, tenant string, perm rbacdomain.Permission) bool {
	panic("authorizer must not be called when identity resolution fails")
}

func (panicIfCalledAuthorizer) IsGlobal(identity string, perm rbacdomain.Permission) bool {
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
	// global: true -- this test only cares about the identity-resolves/
	// checker-grants path, not the cross-tenant check, so it takes the
	// global-grant escape hatch (covered on its own by
	// TestNewRevokeAuthorizer_GlobalGrantSkipsTenantCheck) rather than
	// needing a target-identity lookup wired in too.
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: true})

	authz := newRevokeAuthorizer(&identityAuth, checker, noIdentityTenantLookup, testLogger())
	if !authz.Allowed(httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil)) {
		t.Error("expected Allowed to return true when identity resolves and the checker grants")
	}
}

func TestNewRevokeAuthorizer_DeniesWhenCheckerDenies(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: false})

	authz := newRevokeAuthorizer(&identityAuth, checker, noIdentityTenantLookup, testLogger())
	if authz.Allowed(httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil)) {
		t.Error("expected Allowed to return false when the checker denies")
	}
}

func TestNewRevokeAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{err: errors.New("no identity")}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, panicIfCalledAuthorizer{})

	authz := newRevokeAuthorizer(&identityAuth, checker, noIdentityTenantLookup, testLogger())
	if authz.Allowed(httptest.NewRequest(http.MethodPost, "/credentials/revoke", nil)) {
		t.Error("expected Allowed to return false when identity resolution fails")
	}
}

// noIdentityTenantLookup is a lookup fake for tests that never expect
// newRevokeAuthorizer to reach the target-identity-tenant check (either
// the checker denies first, or the grant is global).
func noIdentityTenantLookup(identity string) (string, bool) { return "", false }

// TestScopeResolver_AuthErrorFailsClosedNotUnfiltered proves newScopeResolver
// (the extracted form of the dashboard's tenant-scope resolver closure,
// see main.go) fails closed on an identity-resolution error: the returned
// filter must be the dashboardFailClosedTenantFilter sentinel, never ""
// (unfiltered/see-everything). checker.IsGlobal must also never be
// reached -- an auth error must short-circuit before any RBAC check runs.
func TestScopeResolver_AuthErrorFailsClosedNotUnfiltered(t *testing.T) {
	identityAuth := fakeRevokeIdentityAuth{err: errors.New("no identity")}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, panicIfCalledAuthorizer{})

	resolver := newScopeResolver(identityAuth, checker)
	got := resolver.TenantFilter(httptest.NewRequest(http.MethodGet, "/dashboard/api/audit", nil))
	if got == "" {
		t.Error("auth error must not resolve to the unfiltered (\"\") tenant filter")
	}
	if got != dashboardFailClosedTenantFilter {
		t.Errorf("expected the fail-closed sentinel %q, got %q", dashboardFailClosedTenantFilter, got)
	}
}

// TestNewUnblockAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants
// mirrors TestNewRevokeAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants:
// newUnblockAuthorizer (main.go) is the extracted, directly-testable form
// of the closure DELETE /dashboard/api/anomalies/blocked/{identity} is
// gated by -- checker.Check must be reached with the caller's own
// (identity, tenant) and rbacdomain.PermissionCredentialRevoke, and a
// grant must result in AllowedFor(r, "") == true (targetTenant == "" means
// the caller's own tenant -- see UnblockAuthorizer's doc comment).
func TestNewUnblockAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "alice", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true})

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/bob", nil)
	if !authz.AllowedFor(req, "") {
		t.Error("expected AllowedFor to return true when identity resolves and the checker grants credential:revoke")
	}
}

// TestNewUnblockAuthorizer_DeniesWhenCheckerDenies mirrors
// TestNewRevokeAuthorizer_DeniesWhenCheckerDenies: a caller who resolves
// but lacks credential:revoke must be denied.
func TestNewUnblockAuthorizer_DeniesWhenCheckerDenies(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: false})

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	if authz.AllowedFor(req, "") {
		t.Error("expected AllowedFor to return false when the checker denies credential:revoke")
	}
}

// TestNewUnblockAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails
// mirrors TestNewRevokeAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails:
// an identity-resolution error must deny outright, without ever reaching
// the checker (panicIfCalledAuthorizer proves this).
func TestNewUnblockAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{err: errors.New("no identity")}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, panicIfCalledAuthorizer{})

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice", nil)
	if authz.AllowedFor(req, "") {
		t.Error("expected AllowedFor to return false when identity resolution fails")
	}
}

// TestNewUnblockAuthorizer_DeniesCrossTenantUnblock mirrors
// TestNewRevokeAuthorizer_DeniesCrossTenantRevoke: bob is a tenant-scoped
// (RoleBinding, not ClusterRoleBinding) admin for tenant "acme" and holds
// credential:revoke, but he names a different tenant ("widgets-inc") as
// the unblock target. Without a global credential:revoke grant, that must
// be denied even though bob's own-tenant permission check passes.
func TestNewUnblockAuthorizer_DeniesCrossTenantUnblock(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: false})

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice?tenant=widgets-inc", nil)
	if authz.AllowedFor(req, "widgets-inc") {
		t.Fatal("bob (tenant acme) must not be allowed to unblock in widgets-inc")
	}
}

// TestNewUnblockAuthorizer_AllowsSameTenantUnblock is the positive
// counterpart: bob (tenant acme) naming "acme" itself as the target must
// be allowed.
func TestNewUnblockAuthorizer_AllowsSameTenantUnblock(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: false})

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice?tenant=acme", nil)
	if !authz.AllowedFor(req, "acme") {
		t.Error("expected bob (tenant acme) to be allowed to unblock within his own tenant")
	}
}

// TestNewUnblockAuthorizer_GlobalGrantSkipsTenantCheck covers the
// ClusterRoleBinding escape hatch: a caller globally granted
// credential:revoke may unblock across tenants.
func TestNewUnblockAuthorizer_GlobalGrantSkipsTenantCheck(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "root", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: true})

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/alice?tenant=widgets-inc", nil)
	if !authz.AllowedFor(req, "widgets-inc") {
		t.Error("expected a globally-granted caller to be allowed to unblock regardless of target tenant")
	}
}

// funcAuthorizer is a domain.Authorizer fake whose Authorize/IsGlobal
// answers are supplied as independent functions -- unlike stubAuthorizer
// (one fixed verdict/global pair shared by every permission), this lets a
// test control the verdict PER PERMISSION, which is exactly what's needed
// to reproduce C1's exploit shape below (a caller holding a global grant
// of one permission and only a tenant-scoped grant of a different one).
type funcAuthorizer struct {
	authorize func(identity, tenant string, perm rbacdomain.Permission) bool
	isGlobal  func(identity string, perm rbacdomain.Permission) bool
}

func (f funcAuthorizer) Authorize(identity, tenant string, perm rbacdomain.Permission) bool {
	return f.authorize(identity, tenant, perm)
}

func (f funcAuthorizer) IsGlobal(identity string, perm rbacdomain.Permission) bool {
	return f.isGlobal(identity, perm)
}

// TestNewUnblockAuthorizer_DeniesCrossTenantUnblockFromGlobalDashboardViewOnly
// is the single most important regression test in the C1 fix wave (final
// whole-branch review, "known-limitations-closure"): it reproduces the
// exact privilege-escalation exploit using only the codebase's two
// built-in roles. alice holds:
//
//   - a GLOBAL grant of dashboard:view (the built-in "viewer" role via a
//     ClusterRoleBinding) -- read-only, every tenant.
//   - a TENANT-SCOPED grant of credential:revoke (the built-in "admin"
//     role via a RoleBinding) in tenant "acme" ONLY.
//
// This is, per the review, "the single most natural way to express 'SRE
// sees everything, tenant admins act within their tenant.'" Before the
// C1 fix, newScopeResolver's IsGlobal(who, dashboard:view) check (reused
// by handleUnblock as the cross-tenant-authority signal) would answer
// true for alice, letting her clear a block in "widgets-inc" -- a tenant
// she holds zero credential:revoke authority in. The fix requires
// cross-tenant authority to come from credential:revoke's OWN IsGlobal,
// which is false for alice, so she must be denied outside her own tenant.
func TestNewUnblockAuthorizer_DeniesCrossTenantUnblockFromGlobalDashboardViewOnly(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "alice", tenant: "acme"}
	authorizer := funcAuthorizer{
		authorize: func(identity, tenant string, perm rbacdomain.Permission) bool {
			switch perm {
			case rbacdomain.PermissionDashboardView:
				return true // global "viewer" grant covers every tenant
			case rbacdomain.PermissionCredentialRevoke:
				return tenant == "acme" // tenant-scoped "admin" grant, acme only
			default:
				return false
			}
		},
		isGlobal: func(identity string, perm rbacdomain.Permission) bool {
			return perm == rbacdomain.PermissionDashboardView // ONLY dashboard:view is global
		},
	}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, authorizer)

	authz := newUnblockAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/api/anomalies/blocked/bob?tenant=widgets-inc", nil)
	if authz.AllowedFor(req, "widgets-inc") {
		t.Fatal("alice (global dashboard:view, tenant-scoped credential:revoke in acme only) must NOT be allowed to unblock in widgets-inc")
	}
	// Sanity: she IS allowed within her own tenant, acme.
	if !authz.AllowedFor(req, "acme") {
		t.Error("alice must still be allowed to unblock within her own tenant (acme)")
	}
}

// TestNewRevokeAuthorizer_DeniesCrossTenantRevoke covers the tenant-scoping
// this task adds: bob is a tenant-scoped (RoleBinding, not
// ClusterRoleBinding) admin for tenant "acme" and holds credential:revoke,
// but alice -- the identity he's trying to revoke -- belongs to a
// different tenant ("widgets-inc"). Without a global grant, that must be
// denied even though the permission check itself passes.
func TestNewRevokeAuthorizer_DeniesCrossTenantRevoke(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: false})
	lookup := func(identity string) (string, bool) {
		if identity == "alice" {
			return "widgets-inc", true // alice belongs to a DIFFERENT tenant than bob
		}
		return "", false
	}

	authz := newRevokeAuthorizer(&identityAuth, checker, lookup, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", strings.NewReader(`{"identity":"alice"}`))
	if authz.Allowed(req) {
		t.Fatal("bob (tenant acme) must not be allowed to revoke alice (tenant widgets-inc)")
	}
}

// TestNewRevokeAuthorizer_AllowsSameTenantRevoke is the positive
// counterpart: bob (tenant acme) revoking alice, who is also in acme,
// must be allowed.
func TestNewRevokeAuthorizer_AllowsSameTenantRevoke(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: false})
	lookup := func(identity string) (string, bool) {
		if identity == "alice" {
			return "acme", true
		}
		return "", false
	}

	authz := newRevokeAuthorizer(&identityAuth, checker, lookup, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", strings.NewReader(`{"identity":"alice"}`))
	if !authz.Allowed(req) {
		t.Error("expected bob (tenant acme) to be allowed to revoke alice, also tenant acme")
	}
}

// TestNewRevokeAuthorizer_GlobalGrantSkipsTenantCheck covers the
// ClusterRoleBinding escape hatch: a globally-granted caller may revoke
// across tenants without the target identity needing to resolve at all.
func TestNewRevokeAuthorizer_GlobalGrantSkipsTenantCheck(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "root", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: true})

	authz := newRevokeAuthorizer(&identityAuth, checker, noIdentityTenantLookup, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", strings.NewReader(`{"identity":"alice"}`))
	if !authz.Allowed(req) {
		t.Error("expected a globally-granted caller to be allowed regardless of the target identity's tenant")
	}
}

// TestNewRevokeAuthorizer_DeniesWhenTargetIdentityUnknown fails closed:
// an identityTenant lookup that doesn't recognize the target identity
// must never be treated as same-tenant.
func TestNewRevokeAuthorizer_DeniesWhenTargetIdentityUnknown(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: false})

	authz := newRevokeAuthorizer(&identityAuth, checker, noIdentityTenantLookup, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", strings.NewReader(`{"identity":"someone-unregistered"}`))
	if authz.Allowed(req) {
		t.Error("expected Allowed to return false when the target identity's tenant can't be resolved")
	}
}

// TestNewRevokeAuthorizer_PreservesRequestBodyForLaterDecode guards the
// exact seam bug this task's brief calls out: newRevokeAuthorizer's
// Allowed closure (via targetIdentityFromRequest) reads r.Body to learn
// the target identity for the cross-tenant check, but HandleRevoke
// (internal/features/credential/adapter/http_handler.go) still needs to
// json.Decode that same body itself, afterward, to get req.Identity for
// the actual revocation. http.Request.Body is a single-read stream -- if
// Allowed drained it without replacing it, HandleRevoke's later decode
// would see EOF and every non-loopback revoke would 400. This test calls
// Allowed and then performs the exact decode HandleRevoke performs next,
// against the same *http.Request, to prove the body survives.
func TestNewRevokeAuthorizer_PreservesRequestBodyForLaterDecode(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true, global: false})
	lookup := func(identity string) (string, bool) {
		if identity == "alice" {
			return "acme", true
		}
		return "", false
	}

	authz := newRevokeAuthorizer(&identityAuth, checker, lookup, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", strings.NewReader(`{"identity":"alice"}`))

	if !authz.Allowed(req) {
		t.Fatal("expected Allowed to return true so we reach the body-reuse check")
	}

	// This mirrors HandleRevoke's own decode step exactly.
	var decoded struct {
		Identity string `json:"identity"`
	}
	if err := json.NewDecoder(req.Body).Decode(&decoded); err != nil {
		t.Fatalf("HandleRevoke's later decode failed -- Allowed must have drained req.Body: %v", err)
	}
	if decoded.Identity != "alice" {
		t.Errorf("expected decoded identity %q, got %q", "alice", decoded.Identity)
	}
}

// TestNewReloadAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants mirrors
// TestNewUnblockAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants:
// a caller who resolves and holds config:edit must be authorized, and the
// resolved identity must be returned for the audit trail's AppliedBy.
func TestNewReloadAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "alice", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true})

	authz := newReloadAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/policy", nil)
	identity, ok := authz.Authorize(req)
	if !ok {
		t.Fatal("expected Authorize to return true when identity resolves and the checker grants config:edit")
	}
	if identity != "alice" {
		t.Errorf("expected resolved identity %q, got %q", "alice", identity)
	}
}

// TestNewReloadAuthorizer_DeniesWhenCheckerDenies mirrors
// TestNewUnblockAuthorizer_DeniesWhenCheckerDenies: a caller who resolves
// but lacks config:edit must be denied, with no identity returned.
func TestNewReloadAuthorizer_DeniesWhenCheckerDenies(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "bob", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: false})

	authz := newReloadAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/policy", nil)
	identity, ok := authz.Authorize(req)
	if ok {
		t.Error("expected Authorize to return false when the checker denies config:edit")
	}
	if identity != "" {
		t.Errorf("expected empty identity on denial, got %q", identity)
	}
}

// TestNewReloadAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails
// mirrors TestNewUnblockAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails:
// an identity-resolution error must deny outright, without ever reaching
// the checker (panicIfCalledAuthorizer proves this).
func TestNewReloadAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{err: errors.New("no identity")}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, panicIfCalledAuthorizer{})

	authz := newReloadAuthorizer(identityAuth, checker)
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/reload/policy", nil)
	identity, ok := authz.Authorize(req)
	if ok {
		t.Error("expected Authorize to return false when identity resolution fails")
	}
	if identity != "" {
		t.Errorf("expected empty identity when identity resolution fails, got %q", identity)
	}
}

// TestNewCallerInfoResolver_ReturnsIdentityAndConfigEditWhenResolved mirrors
// TestNewReloadAuthorizer_GrantsWhenIdentityResolvesAndCheckerGrants's setup,
// but CallerInfoResolver is display-only: it must still return the
// resolved identity even though this call carries no access decision of
// its own.
func TestNewCallerInfoResolver_ReturnsIdentityAndConfigEditWhenResolved(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "alice", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: true})

	resolver := newCallerInfoResolver(identityAuth, checker)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	identity, canConfigEdit := resolver.CallerInfo(req)
	if identity != "alice" {
		t.Errorf("expected resolved identity %q, got %q", "alice", identity)
	}
	if !canConfigEdit {
		t.Error("expected canConfigEdit true when the checker grants config:edit")
	}
}

// TestNewCallerInfoResolver_IdentityWithoutConfigEdit covers a caller who
// resolves but lacks config:edit -- the topbar must still show their
// identity (a read-only viewer), just without the config:edit pill.
func TestNewCallerInfoResolver_IdentityWithoutConfigEdit(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{identity: "viewer", tenant: "acme"}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, stubAuthorizer{verdict: false})

	resolver := newCallerInfoResolver(identityAuth, checker)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	identity, canConfigEdit := resolver.CallerInfo(req)
	if identity != "viewer" {
		t.Errorf("expected resolved identity %q, got %q", "viewer", identity)
	}
	if canConfigEdit {
		t.Error("expected canConfigEdit false when the checker denies config:edit")
	}
}

// TestNewCallerInfoResolver_EmptyWhenIdentityResolutionFails mirrors
// TestNewReloadAuthorizer_DeniesAndSkipsCheckerWhenIdentityResolutionFails:
// an unresolved caller must never get a displayed identity -- a wrong
// displayed name is a trust problem for an operator console even though
// this resolver drives no access decision.
func TestNewCallerInfoResolver_EmptyWhenIdentityResolutionFails(t *testing.T) {
	var identityAuth proxyadapter.IdentityAuthenticator = fakeRevokeIdentityAuth{err: errors.New("no identity")}
	checker := rbacusecase.NewChecker(alwaysOnFlags{}, panicIfCalledAuthorizer{})

	resolver := newCallerInfoResolver(identityAuth, checker)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/status", nil)
	identity, canConfigEdit := resolver.CallerInfo(req)
	if identity != "" {
		t.Errorf("expected empty identity when identity resolution fails, got %q", identity)
	}
	if canConfigEdit {
		t.Error("expected canConfigEdit false when identity resolution fails")
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

func TestRunGenerateSigningKey_WritesValidKeypair(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")

	runGenerateSigningKey(testLogger(), []string{
		"-private-key", privPath,
		"-public-key", pubPath,
	})

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("expected private key file to exist: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("expected the private key to be owner-only (0600), got %04o", perm)
	}

	key, err := loadSigningKey(privPath)
	if err != nil {
		t.Fatalf("expected the generated private key to parse cleanly: %v", err)
	}

	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("expected public key file to exist: %v", err)
	}
	pubKey, err := complianceadapter.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("expected the generated public key to parse cleanly: %v", err)
	}
	if key.N.Cmp(pubKey.N) != 0 {
		t.Error("expected the private key's public half to match the separately-written public key file")
	}
}

// TestRunExportEvidence_SignKey_ProducesVerifiableSignedBundle proves
// export-evidence -sign-key actually reaches WriteBundle: the resulting
// bundle's checksums.txt.sig verifies against the embedded
// public_key.pem, and that public key matches the private key's public
// half exactly.
func TestRunExportEvidence_SignKey_ProducesVerifiableSignedBundle(t *testing.T) {
	dir := t.TempDir()

	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(auditPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "wardline.yaml")
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0600); err != nil {
		t.Fatal(err)
	}

	privPath := filepath.Join(dir, "priv.pem")
	runGenerateSigningKey(testLogger(), []string{"-private-key", privPath, "-public-key", filepath.Join(dir, "pub.pem")})

	outputPath := filepath.Join(dir, "evidence.tar.gz")
	runExportEvidence(testLogger(), []string{
		"-config", configPath,
		"-from", "2020-01-01T00:00:00Z",
		"-to", "2030-01-01T00:00:00Z",
		"-output", outputPath,
		"-sign-key", privPath,
	})

	files, err := complianceadapter.ReadBundle(outputPath)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	sig, ok := files["checksums.txt.sig"]
	if !ok {
		t.Fatal("expected checksums.txt.sig to be present when -sign-key is given")
	}
	pubKey, err := complianceadapter.ParsePublicKeyPEM(files["public_key.pem"])
	if err != nil {
		t.Fatalf("parse embedded public key: %v", err)
	}
	if !complianceadapter.Verify(files["checksums.txt"], sig, pubKey) {
		t.Error("expected the signature to verify against the embedded public key")
	}

	privKey, err := loadSigningKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if privKey.N.Cmp(pubKey.N) != 0 {
		t.Error("expected the embedded public key to match the signing private key's public half")
	}
}

// TestRunExportEvidence_Identities_RedactsSecretAndSpiffeID proves the
// bundle's identities.json carries Name/Tenant only -- a raw "secret:"
// value from credentials.yaml must never appear anywhere in the bundle.
func TestRunExportEvidence_Identities_RedactsSecretAndSpiffeID(t *testing.T) {
	dir := t.TempDir()

	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(auditPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const topSecretValue = "sekrit-registration-value-must-never-leak"
	identitiesPath := filepath.Join(dir, "credentials.yaml")
	identitiesBody := "identities:\n" +
		"  - name: agent-abc123\n" +
		"    secret: " + topSecretValue + "\n" +
		"    tenant: acme\n" +
		"  - name: agent-def456\n" +
		"    secret: another-secret\n"
	if err := os.WriteFile(identitiesPath, []byte(identitiesBody), 0600); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "wardline.yaml")
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n" +
		"features:\n  credential_issuance: true\n" +
		"credential:\n  identities_file: \"" + identitiesPath + "\"\n"
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

	files, err := complianceadapter.ReadBundle(outputPath)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	identitiesJSON, ok := files["identities.json"]
	if !ok {
		t.Fatal("expected identities.json to be present when credential_issuance is on and identities_file is set")
	}
	var got []compliancedomain.RedactedIdentity
	if err := json.Unmarshal(identitiesJSON, &got); err != nil {
		t.Fatalf("identities.json is not valid JSON: %v", err)
	}
	want := []compliancedomain.RedactedIdentity{
		{Name: "agent-abc123", Tenant: "acme"},
		{Name: "agent-def456", Tenant: "default"},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("expected redacted identities %+v, got %+v", want, got)
	}
	for name, content := range files {
		if bytes.Contains(content, []byte(topSecretValue)) {
			t.Errorf("secret value leaked into bundle file %q", name)
		}
	}
}

func TestDeriveInstanceID_OverrideWins(t *testing.T) {
	got := deriveInstanceIDFrom(testLogger(), "operator-supplied-id", func() (string, error) {
		t.Fatal("hostname lookup must not be called when override is set")
		return "", nil
	})
	if got != "operator-supplied-id" {
		t.Errorf("expected the override to win, got %q", got)
	}
}

func TestDeriveInstanceID_FallsBackToHostname(t *testing.T) {
	got := deriveInstanceIDFrom(testLogger(), "", func() (string, error) {
		return "real-hostname", nil
	})
	if got != "real-hostname" {
		t.Errorf("expected the resolved hostname, got %q", got)
	}
}

func TestDeriveInstanceID_HostnameLookupFails_FallsBackToRandomSuffix(t *testing.T) {
	got := deriveInstanceIDFrom(testLogger(), "", func() (string, error) {
		return "", errors.New("no hostname")
	})
	if !strings.HasPrefix(got, "wardline-") {
		t.Errorf("expected a random wardline-<suffix> fallback, got %q", got)
	}
}

func TestDeriveInstanceID_EmptyHostname_FallsBackToRandomSuffix(t *testing.T) {
	got := deriveInstanceIDFrom(testLogger(), "", func() (string, error) {
		return "", nil // no error, but an empty hostname is just as unusable
	})
	if !strings.HasPrefix(got, "wardline-") {
		t.Errorf("expected a random wardline-<suffix> fallback for an empty hostname, got %q", got)
	}
}

// TestPolicyReload_ValidNewPolicyFileTakesEffectOnNextRequest exercises the
// real newPolicyReloadFn (the exact closure runServe wires up, and a later
// task registers with the ReloadCoordinator) against a real temp config +
// policy.yaml, using the real loadPolicyEngine/config.Load construction
// path -- no fakes. It proves the positive half of the hot-reload
// contract: overwriting the on-disk policy file with a genuinely
// different, valid policy and calling the reload closure takes effect on
// the SAME Decider instance's very next Decide call, with zero restart.
func TestPolicyReload_ValidNewPolicyFileTakesEffectOnNextRequest(t *testing.T) {
	dir := t.TempDir()

	policyPath := filepath.Join(dir, "policy.yaml")
	initialPolicy := "rules:\n  - identity: alice\n    tool: read\n    effect: deny\ndefault: allow\n"
	if err := os.WriteFile(policyPath, []byte(initialPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := filepath.Join(dir, "wardline.yaml")
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
		t.Fatal(err)
	}

	engine, err := loadPolicyEngine("yaml", policyPath)
	if err != nil {
		t.Fatalf("initial loadPolicyEngine: %v", err)
	}
	policyHolder := reload.NewReloadableEngine(&engine)
	d := proxyusecase.NewDeciderWithHolder(policyHolder)

	call := proxydomain.ToolCall{Identity: "alice", Tool: "read"}

	before := d.Decide(call)
	if before.Allow {
		t.Fatalf("expected alice/read denied before reload, got %+v", before)
	}

	// Overwrite with a genuinely different, VALID policy: alice/read now
	// allowed.
	newPolicy := "rules:\n  - identity: alice\n    tool: read\n    effect: allow\ndefault: deny\n"
	if err := os.WriteFile(policyPath, []byte(newPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	reloadFn := newPolicyReloadFn(policyHolder, configPath)
	if err := reloadFn(); err != nil {
		t.Fatalf("expected reload with a valid new policy file to succeed, got: %v", err)
	}

	// Same Decider instance, very next call, no restart.
	after := d.Decide(call)
	if !after.Allow {
		t.Fatalf("expected alice/read allowed after reload, got %+v -- reload did not take effect on the next request", after)
	}
}

// TestPolicyReload_InvalidNewPolicyFileLeavesOldEngineServing is the
// security-critical negative case: a malformed on-disk policy file must
// never reach policyHolder.Swap. The reload closure must return an error,
// and the SAME Decider instance -- backed by the untouched old engine --
// must keep deciding every subsequent request exactly as before it was
// ever asked to reload. No crash, no silent partial state.
func TestPolicyReload_InvalidNewPolicyFileLeavesOldEngineServing(t *testing.T) {
	dir := t.TempDir()

	policyPath := filepath.Join(dir, "policy.yaml")
	validPolicy := "rules:\n  - identity: alice\n    tool: read\n    effect: deny\ndefault: allow\n"
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0644); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := filepath.Join(dir, "wardline.yaml")
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
		t.Fatal(err)
	}

	engine, err := loadPolicyEngine("yaml", policyPath)
	if err != nil {
		t.Fatalf("initial loadPolicyEngine: %v", err)
	}
	policyHolder := reload.NewReloadableEngine(&engine)
	d := proxyusecase.NewDeciderWithHolder(policyHolder)

	call := proxydomain.ToolCall{Identity: "alice", Tool: "read"}

	before := d.Decide(call)
	if before.Allow {
		t.Fatalf("expected alice/read denied before reload, got %+v", before)
	}

	// Overwrite with genuinely malformed YAML (unterminated flow sequence).
	malformed := "rules: [identity: alice, tool: read, effect: allow\ndefault: allow\n"
	if err := os.WriteFile(policyPath, []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	reloadFn := newPolicyReloadFn(policyHolder, configPath)
	if err := reloadFn(); err == nil {
		t.Fatal("expected reload with malformed policy YAML to return an error")
	}

	// Old engine, untouched: identical decision, every subsequent request.
	for i := 0; i < 3; i++ {
		after := d.Decide(call)
		if after.Allow != before.Allow || after.Reason != before.Reason {
			t.Fatalf("call %d: old engine's decision changed after a rejected reload: before=%+v after=%+v", i, before, after)
		}
	}
}

// TestRBACReload_PreservesLiveSCIMBindings is the correctness-critical
// case from the hot-reload plan: it proves that reloading RBAC via the
// real newRBACReloadFn reconstructs only the static, YAML-sourced half
// of the authorizer and re-wraps it around the SAME scimBindingStore
// instance already running -- a SCIM-provisioned identity's permission
// must survive an RBAC reload untouched. If a future edit accidentally
// had newRBACReloadFn reconstruct scimBindingStore instead of reusing
// it, this test fails: bob's group membership would vanish.
func TestRBACReload_PreservesLiveSCIMBindings(t *testing.T) {
	dir := t.TempDir()

	// "editor" is a custom role granting dashboard:view -- deliberately
	// distinct from bob's SCIM-granted "viewer" role, so the reload below
	// (which changes rbac.yaml) is a genuinely different, valid file, not
	// a no-op reload.
	rbacPath := filepath.Join(dir, "rbac.yaml")
	initialRBAC := "roles:\n  - name: editor\n    permissions: [\"dashboard:view\"]\n"
	if err := os.WriteFile(rbacPath, []byte(initialRBAC), 0644); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := filepath.Join(dir, "wardline.yaml")
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\ndefault: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n" +
		"rbac:\n  config_file: \"" + rbacPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
		t.Fatal(err)
	}

	// Real construction path: LoadAuthorizer + a real, in-memory SCIM
	// BindingStore, composited exactly as runServe does.
	staticAuthorizer, err := rbacadapter.LoadAuthorizer(rbacPath)
	if err != nil {
		t.Fatalf("initial LoadAuthorizer: %v", err)
	}
	scimBindingStore := scimusecase.NewBindingStore()
	// bob is provisioned into Wardline's builtin "viewer" role (grants
	// dashboard:view) via a real SCIM group -- not present anywhere in
	// rbac.yaml.
	scimBindingStore.SetGroupMembers("wardline:role-viewer", []string{"bob"})

	var authorizer rbacdomain.Authorizer = rbacusecase.NewCompositeAuthorizer(
		staticAuthorizer,
		scimBindingStore,
		staticAuthorizer.RoleHasPermission,
	)
	rbacHolder := reload.NewReloadableEngine(&authorizer)
	checker := rbacusecase.NewCheckerWithHolder(alwaysOnFlags{}, rbacHolder)

	if !checker.Check("bob", "default", rbacdomain.PermissionDashboardView) {
		t.Fatal("expected bob to hold dashboard:view via his live SCIM group binding, before any reload")
	}

	// Overwrite rbac.yaml with a genuinely different, VALID file -- an
	// unrelated role change, nothing to do with bob or SCIM.
	newRBAC := "roles:\n  - name: editor\n    permissions: [\"dashboard:view\", \"credential:revoke\"]\n"
	if err := os.WriteFile(rbacPath, []byte(newRBAC), 0644); err != nil {
		t.Fatal(err)
	}

	reloadFn := newRBACReloadFn(rbacHolder, configPath, true, true, scimBindingStore)
	if err := reloadFn(); err != nil {
		t.Fatalf("expected rbac reload with a valid new file to succeed, got: %v", err)
	}

	// Same Checker instance, very next call: bob's SCIM-granted
	// permission must still hold -- this is the assertion that fails if
	// a future edit reconstructs scimBindingStore instead of reusing it.
	if !checker.Check("bob", "default", rbacdomain.PermissionDashboardView) {
		t.Fatal("expected bob to STILL hold dashboard:view via SCIM after rbac reload -- scimBindingStore was reconstructed or reset instead of reused")
	}
}

// TestRBACReload_InvalidNewRBACFileLeavesOldAuthorizerServing is the
// security-critical negative case, mirroring
// TestPolicyReload_InvalidNewPolicyFileLeavesOldEngineServing: a
// malformed on-disk rbac.yaml must never reach rbacHolder.Swap. The
// reload closure must return an error, and the SAME Checker instance --
// backed by the untouched old composite authorizer, SCIM binding
// included -- must keep deciding every subsequent check exactly as
// before it was ever asked to reload.
func TestRBACReload_InvalidNewRBACFileLeavesOldAuthorizerServing(t *testing.T) {
	dir := t.TempDir()

	rbacPath := filepath.Join(dir, "rbac.yaml")
	validRBAC := "roles:\n  - name: editor\n    permissions: [\"dashboard:view\"]\n"
	if err := os.WriteFile(rbacPath, []byte(validRBAC), 0644); err != nil {
		t.Fatal(err)
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	configPath := filepath.Join(dir, "wardline.yaml")
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\ndefault: allow\n"), 0644); err != nil {
		t.Fatal(err)
	}
	configBody := "listen: \"127.0.0.1:0\"\n" +
		"upstream: \"http://127.0.0.1:1\"\n" +
		"policy_file: \"" + policyPath + "\"\n" +
		"audit:\n  output: \"" + auditPath + "\"\n" +
		"rbac:\n  config_file: \"" + rbacPath + "\"\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0644); err != nil {
		t.Fatal(err)
	}

	staticAuthorizer, err := rbacadapter.LoadAuthorizer(rbacPath)
	if err != nil {
		t.Fatalf("initial LoadAuthorizer: %v", err)
	}
	scimBindingStore := scimusecase.NewBindingStore()
	scimBindingStore.SetGroupMembers("wardline:role-viewer", []string{"bob"})

	var authorizer rbacdomain.Authorizer = rbacusecase.NewCompositeAuthorizer(
		staticAuthorizer,
		scimBindingStore,
		staticAuthorizer.RoleHasPermission,
	)
	rbacHolder := reload.NewReloadableEngine(&authorizer)
	checker := rbacusecase.NewCheckerWithHolder(alwaysOnFlags{}, rbacHolder)

	if !checker.Check("bob", "default", rbacdomain.PermissionDashboardView) {
		t.Fatal("expected bob to hold dashboard:view via SCIM before reload")
	}

	// Overwrite with genuinely malformed YAML (unknown field).
	malformed := "roles:\n  - name: editor\n    bogus_field: true\n"
	if err := os.WriteFile(rbacPath, []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	reloadFn := newRBACReloadFn(rbacHolder, configPath, true, true, scimBindingStore)
	if err := reloadFn(); err == nil {
		t.Fatal("expected reload with malformed rbac YAML to return an error")
	}

	// Old composite authorizer, untouched: bob's SCIM binding and the
	// editor role's grant both still hold, every subsequent call.
	for i := 0; i < 3; i++ {
		if !checker.Check("bob", "default", rbacdomain.PermissionDashboardView) {
			t.Fatalf("call %d: expected bob to still hold dashboard:view after a rejected reload", i)
		}
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
