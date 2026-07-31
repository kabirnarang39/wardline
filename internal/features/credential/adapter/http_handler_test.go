package adapter_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

var errRevokeBackendUnavailable = errors.New("revocation backend unavailable")

type fakeHandlerBootstrapper struct{}

func (fakeHandlerBootstrapper) Authenticate(secret string) (string, string, error) {
	if secret == "good-secret" {
		return "agent-abc123", "", nil
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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "")
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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, fakeRevokeAuthorizer{allowed: true}, noTargetTenant, "")

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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, fakeRevokeAuthorizer{allowed: false}, noTargetTenant, "")

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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "") // rbac not wired -- today's behavior

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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	targetTenant := func(identity string) (string, bool) {
		if identity == "alice" {
			return "acme", true
		}
		return "", false
	}
	h := adapter.NewHandler(issuance, revocation, logger, nil, targetTenant, "")

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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "") // e.g. OIDC bootstrap source, no static registry

	body := bytes.NewBufferString(`{"identity":"mallory"}`)
	req := httptest.NewRequest(http.MethodPost, "/credentials/revoke", body)
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	h.HandleRevoke(w, req)

	if revoker.tenant != "" {
		t.Errorf("expected wildcard revoke (empty tenant), got %q", revoker.tenant)
	}
}

func TestHandleToken_MTLSHeaderPresentAndValidReturns200WithToken(t *testing.T) {
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(&recordingRevoker{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id")

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
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(&recordingRevoker{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id")

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil) // header not set at all
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleToken_MTLSHeaderEmptyReturns401Generic(t *testing.T) {
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(&recordingRevoker{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id")

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil)
	req.Header.Set("X-Wardline-Verified-Spiffe-Id", "")
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleToken_MTLSHeaderUnmappedValueReturns401Generic(t *testing.T) {
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(&recordingRevoker{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id")

	req := httptest.NewRequest(http.MethodPost, "/credentials/token", nil)
	req.Header.Set("X-Wardline-Verified-Spiffe-Id", "wrong-secret") // fakeHandlerBootstrapper rejects anything but "good-secret"
	w := httptest.NewRecorder()

	h.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestHandleToken_MTLSModeIgnoresRequestBodyEntirely proves the request
// body is never consulted when mtlsHeader is set -- an oversized or
// malformed body must not error, since HandleToken must not attempt to
// read or decode it at all on this path.
func TestHandleToken_MTLSModeIgnoresRequestBodyEntirely(t *testing.T) {
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(&recordingRevoker{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := adapter.NewHandler(issuance, revocation, logger, nil, noTargetTenant, "X-Wardline-Verified-Spiffe-Id")

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
