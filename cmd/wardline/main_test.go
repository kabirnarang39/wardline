package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
