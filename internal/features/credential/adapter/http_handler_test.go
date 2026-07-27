package adapter_test

import (
	"bytes"
	"encoding/json"
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

type fakeHandlerBootstrapper struct{}

func (fakeHandlerBootstrapper) Authenticate(secret string) (string, error) {
	if secret == "good-secret" {
		return "agent-abc123", nil
	}
	return "", domain.ErrInvalidCredentials
}

type fakeHandlerIssuer struct{}

func (fakeHandlerIssuer) Issue(identity string) (string, error) {
	return "signed-jwt-for-" + identity, nil
}

type recordingRevoker struct {
	identity  string
	expiresAt time.Time
}

func (r *recordingRevoker) Revoke(identity string, expiresAt time.Time) {
	r.identity, r.expiresAt = identity, expiresAt
}
func (r *recordingRevoker) IsRevoked(identity string) bool { return false }

func newTestHandler(revoker domain.Revoker) *adapter.Handler {
	issuance := usecase.NewIssuanceService(fakeHandlerBootstrapper{}, fakeHandlerIssuer{})
	revocation := usecase.NewRevocationService(revoker)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return adapter.NewHandler(issuance, revocation, logger)
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
