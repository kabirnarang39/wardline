package main

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	rbacusecase "github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
)

func TestBuildTopHandler_WebUIOff_DashboardPathGoesToProxy(t *testing.T) {
	proxyHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })

	h := buildTopHandler(proxy, map[string]http.Handler{})
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
