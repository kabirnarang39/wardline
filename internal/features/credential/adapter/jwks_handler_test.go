package adapter_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeJWKSProvider struct {
	set jwk.Set
	err error
}

func (f fakeJWKSProvider) JWKS() (jwk.Set, error) { return f.set, f.err }

func TestJWKSHandler_ReturnsKeySetAsJSON(t *testing.T) {
	set := jwk.NewSet()
	h := adapter.NewJWKSHandler(fakeJWKSProvider{set: set}, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/credentials/jwks", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	var body struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not a valid JWKS object: %v (body: %s)", err, rec.Body.String())
	}
}

func TestJWKSHandler_MethodNotAllowed(t *testing.T) {
	h := adapter.NewJWKSHandler(fakeJWKSProvider{set: jwk.NewSet()}, discardLogger())
	req := httptest.NewRequest(http.MethodPost, "/credentials/jwks", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rec.Code)
	}
}

func TestJWKSHandler_ProviderError_Returns500(t *testing.T) {
	h := adapter.NewJWKSHandler(fakeJWKSProvider{err: errors.New("boom")}, discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/credentials/jwks", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when the provider errors, got %d", rec.Code)
	}
}