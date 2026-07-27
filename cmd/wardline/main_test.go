package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildTopHandler_WebUIOff_DashboardPathGoesToProxy(t *testing.T) {
	proxyHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("dashboard handler should not be reached when web_ui is off") })

	h := buildTopHandler(proxy, dashboard, false)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !proxyHit {
		t.Error("expected the proxy handler to receive /dashboard/ requests when web_ui is off")
	}
}

func TestBuildTopHandler_WebUIOn_DashboardPathGoesToDashboard(t *testing.T) {
	dashboardHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("proxy handler should not be reached for /dashboard/ when web_ui is on") })
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dashboardHit = true })

	h := buildTopHandler(proxy, dashboard, true)
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !dashboardHit {
		t.Error("expected the dashboard handler to receive /dashboard/ requests when web_ui is on")
	}
}

func TestBuildTopHandler_WebUIOn_OtherPathsStillGoToProxy(t *testing.T) {
	proxyHit := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHit = true })
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("dashboard handler should not be reached for non-dashboard paths") })

	h := buildTopHandler(proxy, dashboard, true)
	req := httptest.NewRequest(http.MethodGet, "/some/mcp/tool", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !proxyHit {
		t.Error("expected the proxy handler to receive non-/dashboard/ requests")
	}
}
