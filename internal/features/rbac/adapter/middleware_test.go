package adapter_test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/rbac/adapter"
	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

// testLogger is a discard logger, kept out of test output the same way
// every other test in this repo that needs a *slog.Logger does.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeIdentityResolver struct {
	identity string
	tenant   string
	err      error
}

func (f fakeIdentityResolver) Authenticate(r *http.Request) (string, string, error) {
	return f.identity, f.tenant, f.err
}

type fakeChecker struct {
	identity, tenant string
	perm             domain.Permission
	verdict          bool
}

func (f *fakeChecker) Check(identity, tenant string, perm domain.Permission) bool {
	f.identity, f.tenant, f.perm = identity, tenant, perm
	return f.verdict
}

func TestRequirePermission_IdentityResolutionFailureReturns401(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	h := adapter.RequirePermission(&fakeChecker{verdict: true}, fakeIdentityResolver{err: errors.New("no token")}, domain.PermissionDashboardView, next, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if nextCalled {
		t.Error("next must not be called when identity resolution fails")
	}
}

func TestRequirePermission_UnauthorizedReturns403(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	h := adapter.RequirePermission(&fakeChecker{verdict: false}, fakeIdentityResolver{identity: "alice"}, domain.PermissionDashboardView, next, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if nextCalled {
		t.Error("next must not be called when the checker denies")
	}
}

func TestRequirePermission_AuthorizedCallsNext(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	h := adapter.RequirePermission(&fakeChecker{verdict: true}, fakeIdentityResolver{identity: "alice"}, domain.PermissionDashboardView, next, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !nextCalled {
		t.Error("expected next to be called when authorized")
	}
}

func TestRequirePermission_ThreadsResolvedIdentityToChecker(t *testing.T) {
	checker := &fakeChecker{verdict: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	resolvedIdentity := "bob"
	tenant := "acme"
	perm := domain.PermissionDashboardView

	h := adapter.RequirePermission(checker, fakeIdentityResolver{identity: resolvedIdentity, tenant: tenant}, perm, next, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if checker.identity != resolvedIdentity {
		t.Errorf("expected checker called with identity %q, got %q", resolvedIdentity, checker.identity)
	}
	if checker.tenant != tenant {
		t.Errorf("expected checker called with tenant %q, got %q", tenant, checker.tenant)
	}
	if checker.perm != perm {
		t.Errorf("expected checker called with perm %v, got %v", perm, checker.perm)
	}
}

func assertSecurityHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("Content-Security-Policy = %q, want \"default-src 'self'\"", got)
	}
}

func TestRequirePermission_IdentityResolutionFailureLogsAndSetsHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := adapter.RequirePermission(&fakeChecker{verdict: true}, fakeIdentityResolver{err: errors.New("no token")}, domain.PermissionDashboardView, next, logger)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assertSecurityHeaders(t, w)
	if !strings.Contains(logBuf.String(), "identity authentication failed") {
		t.Errorf("expected a log line for identity authentication failure, got: %s", logBuf.String())
	}
}

func TestRequirePermission_UnauthorizedLogsIdentityAndSetsHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := adapter.RequirePermission(&fakeChecker{verdict: false}, fakeIdentityResolver{identity: "alice"}, domain.PermissionDashboardView, next, logger)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assertSecurityHeaders(t, w)
	logOut := logBuf.String()
	if !strings.Contains(logOut, "rbac authorization denied") {
		t.Errorf("expected a log line for rbac authorization denial, got: %s", logOut)
	}
	if !strings.Contains(logOut, "identity=alice") {
		t.Errorf("expected the denial log line to include the resolved identity, got: %s", logOut)
	}
}
