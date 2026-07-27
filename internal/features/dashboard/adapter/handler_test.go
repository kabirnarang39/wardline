package adapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/kabirnarang39/wardline/internal/features/dashboard/adapter"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
)

type fakeAuditSource struct {
	entries []domain.LiveEntry
}

func (f *fakeAuditSource) Since(afterID int64, limit int) []domain.LiveEntry {
	var out []domain.LiveEntry
	for _, e := range f.entries {
		if e.ID > afterID {
			out = append(out, e)
		}
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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(audit, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, policy, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{status: status}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
	h := adapter.NewHandler(&fakeAuditSource{}, &fakeStatusSource{}, domain.PolicyInfo{}, testAssets())

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
