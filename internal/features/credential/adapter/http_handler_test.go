package adapter_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

var errRevokeBackendUnavailable = errors.New("revocation backend unavailable")

type fakeHandlerBootstrapper struct{}

func (fakeHandlerBootstrapper) Authenticate(secret string) (string, string, error) {
	switch secret {
	case "good-secret":
		return "agent-abc123", "", nil
	case "attacker-secret":
		// A second, distinct identity this fake bootstrapper genuinely
		// recognizes -- see TestHandleToken_MTLSHeaderRepeatedReturns401Generic:
		// the repeated-header test needs the attacker's pre-set value to
		// itself authenticate successfully (as the WRONG identity) so the
		// test actually discriminates a Header.Get-based regression
		// (silent 200 as agent-attacker) from the fixed behavior (401),
		// rather than both happening to 401 for the unrelated reason that
		// an arbitrary attacker string fails Authenticate anyway.
		return "agent-attacker", "", nil
	}
	return "", "", domain.ErrInvalidCredentials
}

type fakeHandlerIssuer struct{}

func (fakeHandlerIssuer) Issue(identity, tenant string) (string, error) {
	return "signed-jwt-for-" + identity, nil
}

type recordingRevoker struct {
	tenant    string
	identity  string
	expiresAt time.Time
	err       error // when set, Revoke returns this instead of recording
}

func (r *recordingRevoker) Revoke(tenantName, identity string, expiresAt time.Time) error {
	if r.err != nil {
		return r.err
	}
	r.tenant, r.identity, r.expiresAt = tenantName, identity, expiresAt
	return nil
}
func (r *recordingRevoker) IsRevoked(tenantName, identity string) bool { return false }

// noTargetTenant matches the pre-Task-4 wildcard-revoke behavior: no
// static registry entry for any identity.
func noTargetTenant(string) (string, bool) { return "", false }

func newTestHandler(revoker domain.Revoker) *adapter.Handler {
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "", time.Hour)
}

func TestHandleToken_ValidSecretReturns200WithToken(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	body := bytes.NewBufferString(`{"secret":"good-secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", body)
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.Token != "signed-jwt-for-agent-abc123" {
		t.Errorf("unexpected token: %q", resp.Token)
	}
}

func TestHandleToken_WrongSecretReturns401Generic(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	body := bytes.NewBufferString(`{"secret":"wrong-secret"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", body)
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("agent-abc123")) {
		t.Error("401 response must not leak whether an identity exists")
	}
}

func TestHandleToken_MalformedBodyReturns400(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleToken_WrongMethodReturns405(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodGet, "/credentials/token", nil)
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleRevoke_FromLoopbackRevokes(t *testing.T) {
	revoker := &recordingRevoker{}
	h := newTestHandler(revoker)
	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
	}
	if revoker.identity != "agent-abc123" {
		t.Errorf("expected agent-abc123 to have been revoked, got %q", revoker.identity)
	}
	if !revoker.expiresAt.After(time.Now()) {
		t.Error("expected the revocation expiry to be in the future")
	}
}

func TestHandleRevoke_PersistFailureReturns500NotFalse204(t *testing.T) {
	revoker := &recordingRevoker{err: errRevokeBackendUnavailable}
	h := newTestHandler(revoker)
	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the revocation fails to persist (never a false-positive 204), got %d", w.Code)
	}
}

func TestHandleRevoke_FromNonLoopbackIsForbidden(t *testing.T) {
	revoker := &recordingRevoker{}
	h := newTestHandler(revoker)
	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "203.0.113.5:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if revoker.identity != "" {
		t.Error("expected no revocation to have happened for a non-loopback caller")
	}
}

func TestHandleRevoke_MissingIdentityReturns400(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", bytes.NewBufferString(`{}`))
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRevoke_WrongMethodReturns405(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodGet, "/credentials/revoke", nil)
	req.RemoteAddr = "127.0.0.1:54321" // loopback, so the method check (not the loopback check) is what's under test
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleRevoke_FromNonLoopbackWrongMethodStillReturns403(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodGet, "/credentials/revoke", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (loopback check must run before the method check), got %d", w.Code)
	}
}

func TestHandleRevoke_MalformedBodyReturns400(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", bytes.NewBufferString("not json"))
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRevoke_IPv6LoopbackSucceeds(t *testing.T) {
	revoker := &recordingRevoker{}
	h := newTestHandler(revoker)
	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "[::1]:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
	}
	if revoker.identity != "agent-abc123" {
		t.Errorf("expected agent-abc123 to have been revoked, got %q", revoker.identity)
	}
}

func TestHandleToken_OversizedBodyRejected(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	// One byte over the 64 KiB cap; content doesn't matter since the reader
	// should be cut off before the body is parsed as JSON.
	oversized := bytes.Repeat([]byte("a"), (64<<10)+1)
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", bytes.NewReader(oversized))
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
}

func TestHandleRevoke_OversizedBodyRejected(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	// One byte over the 64 KiB cap; content doesn't matter since the reader
	// should be cut off before the body is parsed as JSON.
	oversized := bytes.Repeat([]byte("a"), (64<<10)+1)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", bytes.NewReader(oversized))
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", w.Code)
	}
}

type fakeRevokeAuthorizer struct {
	allowed bool
}

func (f fakeRevokeAuthorizer) Allowed(r *http.Request) bool { return f.allowed }

func TestHandleRevoke_NonLoopbackAllowedByAuthorizerRevokes(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, fakeRevokeAuthorizer{allowed: true}, noTargetTenant, "", time.Hour)

	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "203.0.113.5:54321" // non-loopback
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (body: %s)", w.Code, w.Body.String())
	}
	if revoker.identity != "agent-abc123" {
		t.Errorf("expected agent-abc123 to have been revoked, got %q", revoker.identity)
	}
}

func TestHandleRevoke_NonLoopbackDeniedByAuthorizerIsForbidden(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, fakeRevokeAuthorizer{allowed: false}, noTargetTenant, "", time.Hour)

	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "203.0.113.5:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if revoker.identity != "" {
		t.Error("expected no revocation when the authorizer denies")
	}
}

func TestHandleRevoke_NonLoopbackNoAuthorizerWiredIsForbidden(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "", time.Hour) // rbac not wired -- today's behavior

	body := bytes.NewBufferString(`{"identity":"agent-abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "203.0.113.5:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleRevoke_ResolvesTargetTenantBeforeRevoking(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	targetTenant := func(identity string) (string, bool) {
		if identity == "alice" {
			return "acme", true
		}
		return "", false
	}
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, targetTenant, "", time.Hour)

	body := bytes.NewBufferString(`{"identity":"alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if revoker.tenant != "acme" || revoker.identity != "alice" {
		t.Errorf("Revoke called with (%q,%q), want (\"acme\",\"alice\")", revoker.tenant, revoker.identity)
	}
}

func TestHandleRevoke_UnresolvableTargetTenantRevokesAsWildcard(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "", time.Hour) // e.g. OIDC bootstrap source, no static registry

	body := bytes.NewBufferString(`{"identity":"mallory"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if revoker.tenant != "" {
		t.Errorf("expected wildcard revoke (empty tenant), got %q", revoker.tenant)
	}
}

// TestHandleRevoke_UnresolvableTargetTenantHonorsExplicitTenant covers the
// fix for the residual wildcard gap documented on credential-issuance.md's
// "Known limitations": when h.targetTenant can't resolve a tenant (OIDC
// bootstrap source, or an ambiguous identity name), a caller that already
// named the intended tenant in the request body gets a scoped revoke, not
// a full wildcard across every tenant's copy of that identity.
func TestHandleRevoke_UnresolvableTargetTenantHonorsExplicitTenant(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "", time.Hour) // e.g. OIDC bootstrap source, no static registry

	body := bytes.NewBufferString(`{"identity":"alice","tenant":"acme"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if revoker.tenant != "acme" || revoker.identity != "alice" {
		t.Errorf("Revoke called with (%q,%q), want (\"acme\",\"alice\")", revoker.tenant, revoker.identity)
	}
}

// TestHandleRevoke_ResolvedTargetTenantIgnoresExplicitTenant covers the
// other half of the same fix: when h.targetTenant DOES resolve a tenant,
// the static registry is authoritative -- an explicit (and here,
// deliberately conflicting) req.Tenant from the client must never
// override it.
func TestHandleRevoke_ResolvedTargetTenantIgnoresExplicitTenant(t *testing.T) {
	revoker := &recordingRevoker{}
	refreshStore := adapter.NewInMemoryRefreshStore()
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	targetTenant := func(identity string) (string, bool) {
		if identity == "alice" {
			return "acme", true
		}
		return "", false
	}
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, targetTenant, "", time.Hour)

	body := bytes.NewBufferString(`{"identity":"alice","tenant":"widgets-inc"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if revoker.tenant != "acme" {
		t.Errorf("registry-resolved tenant must win over client-supplied tenant: got %q, want \"acme\"", revoker.tenant)
	}
}

func TestHandleToken_MTLSHeaderPresentAndValidReturns200WithToken(t *testing.T) {
	refreshStore := adapter.NewInMemoryRefreshStore()
	revoker := &recordingRevoker{}
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil)
	req.Header.Set("X-Wardline-Verified-Spiffe-Id", "good-secret") // fakeHandlerBootstrapper treats "good-secret" as valid regardless of source
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.Token != "signed-jwt-for-agent-abc123" {
		t.Errorf("unexpected token: %q", resp.Token)
	}
}

func TestHandleToken_MTLSHeaderMissingReturns401Generic(t *testing.T) {
	refreshStore := adapter.NewInMemoryRefreshStore()
	revoker := &recordingRevoker{}
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil) // header not set at all
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleToken_MTLSHeaderEmptyReturns401Generic(t *testing.T) {
	refreshStore := adapter.NewInMemoryRefreshStore()
	revoker := &recordingRevoker{}
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil)
	req.Header.Set("X-Wardline-Verified-Spiffe-Id", "")
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleToken_MTLSHeaderUnmappedValueReturns401Generic(t *testing.T) {
	refreshStore := adapter.NewInMemoryRefreshStore()
	revoker := &recordingRevoker{}
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil)
	req.Header.Set("X-Wardline-Verified-Spiffe-Id", "wrong-secret") // fakeHandlerBootstrapper rejects anything but "good-secret"
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleToken_MTLSHeaderRepeatedReturns401Generic proves the
// append-mode mesh case fails closed: an attacker that pre-sets the
// trusted header sends its value FIRST, so a Header.Get-based read would
// hand the attacker's string to the bootstrapper and ignore the mesh's
// appended, genuinely-verified one. Two values must be rejected, not
// disambiguated. The attacker's pre-set value ("attacker-secret") is
// itself a secret fakeHandlerBootstrapper genuinely authenticates (as a
// different identity, agent-attacker) -- deliberately, so this test
// actually discriminates: a Header.Get-based regression would return 200
// with a token for the WRONG identity here, not just an unrelated 401,
// which is what makes this the operationally dangerous shape of the bug
// and what a naive "first value happens to be garbage" test would miss.
func TestHandleToken_MTLSHeaderRepeatedReturns401Generic(t *testing.T) {
	refreshStore := adapter.NewInMemoryRefreshStore()
	revoker := &recordingRevoker{}
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil)
	req.Header.Add("X-Wardline-Verified-Spiffe-Id", "attacker-secret") // arrives first; itself authenticates, as the WRONG identity
	req.Header.Add("X-Wardline-Verified-Spiffe-Id", "good-secret")     // mesh's appended, real value
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a repeated trusted header, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestHandleToken_MTLSModeIgnoresRequestBodyEntirely proves the request
// body is never consulted when mtlsHeader is set -- an oversized or
// malformed body must not error, since HandleToken must not attempt to
// read or decode it at all on this path.
func TestHandleToken_MTLSModeIgnoresRequestBodyEntirely(t *testing.T) {
	refreshStore := adapter.NewInMemoryRefreshStore()
	revoker := &recordingRevoker{}
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{}, refreshStore, time.Hour)
	revocation := usecase.NewRevocationService(revoker, refreshStore)
	refresh := usecase.NewRefreshService(refreshStore, revoker, fakeHandlerIssuer{}, time.Hour, time.Now)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, refresh, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id", time.Hour)

	oversized := bytes.Repeat([]byte("a"), (64<<10)+1) // exceeds maxTokenRequestBodyBytes
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", bytes.NewReader(oversized))
	req.Header.Set("X-Wardline-Verified-Spiffe-Id", "good-secret")
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (body must be ignored entirely in mtls mode), got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestHandleToken_EmptyMtlsHeaderPreservesBodyDecodingBehavior is a
// regression guard, not a new-feature test: with mtlsHeader == "" (the
// zero value, what every presharedsecret/oidc call site passes), an
// oversized body must still be rejected exactly as it always has been --
// proving the new branch's else path is unchanged.
func TestHandleToken_EmptyMtlsHeaderPreservesBodyDecodingBehavior(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	oversized := bytes.Repeat([]byte("a"), (64<<10)+1)
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", bytes.NewReader(oversized))
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body when mtlsHeader is unset, got %d", w.Code)
	}
}

func TestHandleToken_ResponseIncludesRefreshToken(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodPost, "/credentials/token", strings.NewReader(`{"secret":"good-secret"}`))
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected a non-empty access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected a non-empty refresh token from bootstrap")
	}
}

func TestHandleRefresh_ValidRefreshTokenReturns200WithNewTokens(t *testing.T) {
	// Set this test up by first bootstrapping through the SAME handler
	// (so the refresh token it needs is real, issued through the real
	// IssuanceService/RefreshStore this Handler was constructed with),
	// then posting that refresh token to /credentials/refresh.
	h := newTestHandler(&recordingRevoker{})
	bootstrapReq := httptest.NewRequest(http.MethodPost, "/credentials/token", strings.NewReader(`{"secret":"good-secret"}`))
	bootstrapW := httptest.NewRecorder()
	h.HandleToken(bootstrapW, bootstrapReq)
	var bootstrapResp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(bootstrapW.Body.Bytes(), &bootstrapResp); err != nil {
		t.Fatalf("invalid bootstrap response: %v", err)
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/credentials/refresh", strings.NewReader(`{"refresh_token":"`+bootstrapResp.RefreshToken+`"}`))
	refreshW := httptest.NewRecorder()
	h.HandleRefresh(refreshW, refreshReq)

	if refreshW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", refreshW.Code, refreshW.Body.String())
	}
	var refreshResp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refreshW.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("invalid refresh response: %v", err)
	}
	if refreshResp.Token == "" || refreshResp.RefreshToken == "" {
		t.Error("expected non-empty new access and refresh tokens")
	}
	if refreshResp.RefreshToken == bootstrapResp.RefreshToken {
		t.Error("expected refresh to rotate to a DIFFERENT refresh token")
	}
}

func TestHandleRefresh_ReusedOldRefreshTokenAfterRotationReturns401(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	bootstrapReq := httptest.NewRequest(http.MethodPost, "/credentials/token", strings.NewReader(`{"secret":"good-secret"}`))
	bootstrapW := httptest.NewRecorder()
	h.HandleToken(bootstrapW, bootstrapReq)
	var bootstrapResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(bootstrapW.Body.Bytes(), &bootstrapResp)

	firstRefreshReq := httptest.NewRequest(http.MethodPost, "/credentials/refresh", strings.NewReader(`{"refresh_token":"`+bootstrapResp.RefreshToken+`"}`))
	h.HandleRefresh(httptest.NewRecorder(), firstRefreshReq)

	secondRefreshReq := httptest.NewRequest(http.MethodPost, "/credentials/refresh", strings.NewReader(`{"refresh_token":"`+bootstrapResp.RefreshToken+`"}`))
	secondW := httptest.NewRecorder()
	h.HandleRefresh(secondW, secondRefreshReq)

	if secondW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 reusing an already-rotated-away refresh token, got %d", secondW.Code)
	}
}

func TestHandleRefresh_UnknownTokenReturns401(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodPost, "/credentials/refresh", strings.NewReader(`{"refresh_token":"never-issued"}`))
	w := httptest.NewRecorder()

	h.HandleRefresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleRefresh_WrongMethodReturns405(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	req := httptest.NewRequest(http.MethodGet, "/credentials/refresh", nil)
	w := httptest.NewRecorder()

	h.HandleRefresh(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleRefresh_OversizedBodyReturns400(t *testing.T) {
	h := newTestHandler(&recordingRevoker{})
	oversized := bytes.Repeat([]byte("a"), (64<<10)+1)
	req := httptest.NewRequest(http.MethodPost, "/credentials/refresh", bytes.NewReader(oversized))
	w := httptest.NewRecorder()

	h.HandleRefresh(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an oversized body, got %d", w.Code)
	}
}
