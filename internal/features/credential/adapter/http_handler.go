package adapter

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

// maxTokenRequestBodyBytes caps how much of the request body we'll read on
// the credential HTTP endpoints before decoding — both are unauthenticated
// (token) or take an untrusted body (revoke), and a {"secret":"..."} or
// {"identity":"..."} body is tiny, so 64 KiB is generous headroom, not a
// real limit in practice.
const maxTokenRequestBodyBytes = 64 << 10

type tokenRequest struct {
	Secret string `json:"secret"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type revokeRequest struct {
	Identity string `json:"identity"`
}

// RevokeAuthorizer decides whether a non-loopback caller may still
// revoke a credential. Wired only when the rbac feature is on; nil
// means "not wired," which preserves today's loopback-only behavior
// exactly (see design doc docs/superpowers/specs/2026-07-28-rbac-design.md).
type RevokeAuthorizer interface {
	Allowed(r *http.Request) bool
}

// Handler serves the credential-issuance HTTP surface: POST
// /credentials/token (agent-facing, network-reachable) and POST
// /credentials/revoke (operator-facing, loopback-only by default — see
// design doc "Error handling": an unauthenticated, network-exposed revoke
// endpoint would itself be the class of gap this feature exists to
// close). When a RevokeAuthorizer is wired (rbac feature on), a
// non-loopback caller may also reach /credentials/revoke, provided it
// authenticates and holds credential:revoke — see
// docs/superpowers/specs/2026-07-28-rbac-design.md.
type Handler struct {
	issuance         *usecase.IssuanceService
	revocation       *usecase.RevocationService
	logger           *slog.Logger
	revokeAuthorizer RevokeAuthorizer
	// targetTenant resolves the tenant of the identity being revoked (not
	// the caller's own tenant). ok==false (no static registry entry, e.g.
	// OIDC bootstrap source) falls back to the wildcard revoke ("") --
	// see domain.Revoker's doc comment.
	targetTenant func(identity string) (tenant string, ok bool)
	now          func() time.Time
}

func NewHandler(issuance *usecase.IssuanceService, revocation *usecase.RevocationService, logger *slog.Logger, revokeAuthorizer RevokeAuthorizer, targetTenant func(identity string) (tenant string, ok bool)) *Handler {
	return &Handler{issuance: issuance, revocation: revocation, logger: logger, revokeAuthorizer: revokeAuthorizer, targetTenant: targetTenant, now: time.Now}
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBodyBytes) // 64 KiB — generous for a {"secret":"..."} body
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token, err := h.issuance.Bootstrap(req.Secret)
	if err != nil {
		// Generic message regardless of cause (unknown identity vs. wrong
		// secret) — avoids identity enumeration, see design doc. The secret
		// itself must never be logged.
		h.logger.Warn("credential bootstrap failed", "remote_addr", r.RemoteAddr)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{Token: token})
}

func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	// Loopback check before the method check — a non-loopback caller must
	// get a uniform 403 regardless of HTTP method, not a 405 that leaks
	// that this endpoint exists. A non-loopback caller may still proceed
	// if an RBAC authorizer is wired and grants it — the loopback path
	// itself is completely unchanged and unweakened (see design doc
	// docs/superpowers/specs/2026-07-28-rbac-design.md).
	if !isLoopback(r.RemoteAddr) && (h.revokeAuthorizer == nil || !h.revokeAuthorizer.Allowed(r)) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBodyBytes) // 64 KiB — generous for a {"identity":"..."} body
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Identity == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: identity is required")
		return
	}
	// expiresAt is now+tokenTTL: the worst-case remaining lifetime of any
	// token already issued to this identity — every outstanding and
	// future-until-expiry token is rejected from this point on. See
	// design doc "Error handling".
	// targetTenant resolves the identity being revoked's own tenant so
	// the revoke is scoped and doesn't over-revoke other tenants sharing
	// the identity name. ok==false (e.g. OIDC bootstrap source, no
	// static registry) falls back to "" -- domain.Revoker's documented
	// wildcard, matching the pre-scoping behavior for those cases.
	targetTenant, _ := h.targetTenant(req.Identity)
	if err := h.revocation.Revoke(targetTenant, req.Identity, h.now().Add(tokenTTL)); err != nil {
		// A 204 here would tell the caller a security action succeeded
		// when it didn't -- an operator revoking a compromised identity
		// needs to know the revocation was NOT persisted, not silently
		// believe it took effect.
		h.logger.Error("revocation failed to persist", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "revocation failed to persist")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// isLoopback reports whether remoteAddr (an http.Request.RemoteAddr,
// "host:port") resolves to a loopback address. Used to keep
// /credentials/revoke off the network by default this cycle.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
