package adapter

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
)

// ManagerPort is the narrow slice of the approval usecase.Manager the HTTP
// surface needs -- listing what's pending and deciding a single request.
type ManagerPort interface {
	ListPending(tenant string) []domain.Request
	Approve(id, by string) error
	Deny(id, by string) error
}

// NewHTTPHandler serves the operator approval surface: GET
// /approvals/pending, POST /approvals/{id}/approve, POST
// /approvals/{id}/deny. Loopback-only by default -- an unauthenticated,
// network-exposed approve endpoint would itself be the class of gap this
// feature exists to close. When authorizer is non-nil (rbac feature on), a
// non-loopback caller it grants may also reach these routes; the loopback
// path is unchanged. decided-by is "loopback" for Phase 1.
func NewHTTPHandler(mgr ManagerPort, authorizer func(*http.Request) bool, logger *slog.Logger) http.Handler {
	guard := func(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !isLoopback(r.RemoteAddr) && (authorizer == nil || !authorizer(r)) {
				writeJSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			next(w, r)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /approvals/pending", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mgr.ListPending("")); err != nil {
			logger.Error("failed to encode pending approvals", "error", err)
		}
	}))

	mux.HandleFunc("POST /approvals/{id}/approve", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Approve(r.PathValue("id"), "loopback"); err != nil {
			writeJSONError(w, http.StatusNotFound, "unknown or already-decided approval")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("POST /approvals/{id}/deny", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Deny(r.PathValue("id"), "loopback"); err != nil {
			writeJSONError(w, http.StatusNotFound, "unknown or already-decided approval")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	return mux
}

// isLoopback reports whether remoteAddr (an http.Request.RemoteAddr,
// "host:port") resolves to a loopback address.
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
