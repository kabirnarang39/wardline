package adapter_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/rbac/adapter"
	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

type fakeIdentityResolver struct {
	identity string
	err      error
}

func (f fakeIdentityResolver) Authenticate(r *http.Request) (string, error) {
	return f.identity, f.err
}

type fakeChecker struct {
	verdict bool
}

func (f fakeChecker) Check(identity, tenant string, perm domain.Permission) bool {
	return f.verdict
}

func TestRequirePermission_IdentityResolutionFailureReturns401(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })

	h := adapter.RequirePermission(fakeChecker{verdict: true}, fakeIdentityResolver{err: errors.New("no token")}, "default", domain.PermissionDashboardView, next)
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

	h := adapter.RequirePermission(fakeChecker{verdict: false}, fakeIdentityResolver{identity: "alice"}, "default", domain.PermissionDashboardView, next)
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

	h := adapter.RequirePermission(fakeChecker{verdict: true}, fakeIdentityResolver{identity: "alice"}, "default", domain.PermissionDashboardView, next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !nextCalled {
		t.Error("expected next to be called when authorized")
	}
}
