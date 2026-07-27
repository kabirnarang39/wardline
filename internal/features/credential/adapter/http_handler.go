package adapter

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

type tokenRequest struct {
	Secret string `json:"secret"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type revokeRequest struct {
	Identity string `json:"identity"`
}

// Handler serves the credential-issuance HTTP surface: POST
// /credentials/token (agent-facing, network-reachable) and POST
// /credentials/revoke (operator-facing, loopback-only — see design doc
// "Error handling": an unauthenticated, network-exposed revoke endpoint
// would itself be the class of gap this feature exists to close).
type Handler struct {
	issuance   *usecase.IssuanceService
	revocation *usecase.RevocationService
	now        func() time.Time
}

func NewHandler(issuance *usecase.IssuanceService, revocation *usecase.RevocationService) *Handler {
	return &Handler{issuance: issuance, revocation: revocation, now: time.Now}
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	token, err := h.issuance.Bootstrap(req.Secret)
	if err != nil {
		// Generic message regardless of cause (unknown identity vs. wrong
		// secret) — avoids identity enumeration, see design doc.
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{Token: token})
}

func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !isLoopback(r.RemoteAddr) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Identity == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: identity is required")
		return
	}
	// expiresAt is now+tokenTTL: the worst-case remaining lifetime of any
	// token already issued to this identity — every outstanding and
	// future-until-expiry token is rejected from this point on. See
	// design doc "Error handling".
	h.revocation.Revoke(req.Identity, h.now().Add(tokenTTL))
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
