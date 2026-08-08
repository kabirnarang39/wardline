package adapter

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKSProvider is the subset of *JWTIssuerVerifier the JWKS endpoint
// needs -- a narrow interface so the handler doesn't depend on the whole
// issuer/verifier surface, and tests can supply a fake.
type JWKSProvider interface {
	JWKS() (jwk.Set, error)
}

// JWKSHandler serves GET /credentials/jwks -- a standard JWKS-shaped
// ({"keys":[...]}, RFC 7517) listing of every currently-valid
// verification key (the signing key plus every rotation-window previous
// key) by kid. Unauthenticated by design: a JWKS endpoint's whole
// purpose is public discoverability of PUBLIC keys, which are not
// secrets. See docs/superpowers/specs/2026-08-08-ha-rotation-blockstate-design.md.
type JWKSHandler struct {
	provider JWKSProvider
	logger   *slog.Logger
}

func NewJWKSHandler(provider JWKSProvider, logger *slog.Logger) *JWKSHandler {
	return &JWKSHandler{provider: provider, logger: logger}
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	set, err := h.provider.JWKS()
	if err != nil {
		h.logger.Error("failed to build JWKS", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to build key set")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(set); err != nil {
		h.logger.Warn("failed to encode JWKS response", "error", err)
	}
}
