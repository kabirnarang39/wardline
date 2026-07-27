package adapter

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
)

// AuditSource is the subset of RingBuffer's behavior Handler depends on —
// a narrow interface so tests can supply a fake without importing the
// real usecase package, matching the BudgetChecker pattern in
// proxy/adapter/handler.go.
type AuditSource interface {
	Since(afterID int64, limit int) []domain.LiveEntry
}

// StatusSource is the subset of StatusProvider's behavior Handler depends
// on.
type StatusSource interface {
	Status() domain.StatusInfo
}

// defaultAuditLimit and maxAuditLimit bound the /api/audit endpoint's
// limit query parameter: a missing or invalid value defaults to 100; any
// requested value above 1000 (the ring buffer's own capacity — see
// dashboard/usecase.RingBuffer, wired with capacity 1000 in
// cmd/wardline/main.go) is clamped, since the buffer can never hold more
// than that anyway.
const (
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
)

// Handler serves the dashboard's read-only JSON API and its embedded SPA,
// all read-only by construction — it has no dependency on any policy,
// budget, or proxy domain type, so it cannot influence a proxied request.
type Handler struct {
	audit  AuditSource
	status StatusSource
	policy domain.PolicyInfo
	mux    *http.ServeMux
}

func NewHandler(audit AuditSource, status StatusSource, policy domain.PolicyInfo, assets fs.FS) *Handler {
	h := &Handler{audit: audit, status: status, policy: policy}

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/api/audit", h.handleAudit)
	mux.HandleFunc("/dashboard/api/policy", h.handlePolicy)
	mux.HandleFunc("/dashboard/api/status", h.handleStatus)
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard", spaHandler(assets)))
	h.mux = mux

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil {
		after = 0
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}

	entries := h.audit.Since(after, limit)
	if entries == nil {
		entries = []domain.LiveEntry{}
	}
	writeJSON(w, entries)
}

func (h *Handler) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, h.policy)
}

func (h *Handler) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, h.status.Status())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// spaHandler serves static assets from assets, falling back to
// index.html for any path assets doesn't have — the SPA's own
// client-side view state (Activity/Policy/Status) isn't real server
// routes, so any unrecognized sub-path under /dashboard/ is a client
// route, not a 404.
//
// index.html's bytes are read once at construction and written directly
// on the root/fallback path rather than delegated to http.FileServer:
// FileServer redirects any request whose path is exactly ".../index.html"
// to its containing directory, so handing it a re-pointed "/index.html"
// path (the naive fallback approach) produces a redirect loop instead of
// the page.
func spaHandler(assets fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(assets))
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := assets.Open(p); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
