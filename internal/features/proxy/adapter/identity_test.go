package adapter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

func TestHeaderIdentity_ReadsHeaderAlwaysSucceeds(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Wardline-Identity", "agent-abc123")

	identity, _, err := HeaderIdentity{}.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != "agent-abc123" {
		t.Errorf("expected agent-abc123, got %q", identity)
	}
}

func TestHeaderIdentity_MissingHeaderStillSucceedsEmpty(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	identity, _, err := HeaderIdentity{}.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != "" {
		t.Errorf("expected empty identity, got %q", identity)
	}
}

func TestHeaderIdentity_DefaultsTenant(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Wardline-Identity", "alice")
	identity, gotTenant, err := HeaderIdentity{}.Authenticate(req)
	if err != nil || identity != "alice" || gotTenant != tenant.Default {
		t.Fatalf("got (%q, %q, %v), want (\"alice\", %q, nil)", identity, gotTenant, err, tenant.Default)
	}
}

func TestHeaderIdentity_ReadsTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Wardline-Identity", "alice")
	req.Header.Set("X-Wardline-Tenant", "acme")
	_, gotTenant, err := HeaderIdentity{}.Authenticate(req)
	if err != nil || gotTenant != "acme" {
		t.Fatalf("got (%q, %v), want (\"acme\", nil)", gotTenant, err)
	}
}

type fakeAuthenticator struct {
	identity string
	tenant   string
	err      error
}

func (f fakeAuthenticator) Authenticate(bearerToken string) (string, string, error) {
	return f.identity, f.tenant, f.err
}

func TestBearerIdentity_ValidBearerTokenSucceeds(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer some-jwt")

	auth := NewBearerIdentity(fakeAuthenticator{identity: "agent-abc123"})
	identity, _, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != "agent-abc123" {
		t.Errorf("expected agent-abc123, got %q", identity)
	}
}

func TestBearerIdentity_MissingAuthorizationHeaderFails(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	auth := NewBearerIdentity(fakeAuthenticator{identity: "should-not-be-used"})
	_, _, err := auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected an error for a missing Authorization header")
	}
}

func TestBearerIdentity_MalformedAuthorizationHeaderFails(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // not a Bearer token
	auth := NewBearerIdentity(fakeAuthenticator{identity: "should-not-be-used"})
	_, _, err := auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected an error for a non-Bearer Authorization header")
	}
}

func TestBearerIdentity_AuthenticatorFailurePropagates(t *testing.T) {
	wantErr := errors.New("token invalid")
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer bad-jwt")
	auth := NewBearerIdentity(fakeAuthenticator{err: wantErr})
	_, _, err := auth.Authenticate(req)
	if !errors.Is(err, wantErr) {
		t.Errorf("expected the Authenticator's error to propagate, got %v", err)
	}
}
