package adapter

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"
)

// pingTimeout bounds how long /readyz waits on the optional pinger
// before treating it as failed -- a readiness probe that itself hangs
// indefinitely on a slow dependency would make the probe timeout (and
// thus the pod's ready/not-ready flapping) entirely dependent on
// whatever the caller configured, instead of a bound this package owns.
const pingTimeout = 2 * time.Second

// Handler serves /healthz (liveness) and /readyz (readiness). Never
// depends on policy, audit, budget, or proxy state -- registered as an
// unconditional extraRoute in cmd/wardline/main.go, the same way the
// dashboard is, so neither route is ever proxied to the upstream or
// recorded in the audit trail.
type Handler struct {
	draining atomic.Bool
	pinger   func(ctx context.Context) error
}

// NewHandler builds a Handler. pinger may be nil (no external dependency
// to check, e.g. postgres_storage is off) -- /readyz then reports ready
// based solely on the draining flag.
func NewHandler(pinger func(ctx context.Context) error) *Handler {
	return &Handler{pinger: pinger}
}

// SetDraining marks the process as draining (true) or ready (false).
// Called once from cmd/wardline/main.go's shutdown-signal handler, the
// very first action taken on SIGTERM/SIGINT -- before the existing HTTP
// drain begins -- so a polling Kubernetes readiness probe sees the pod go
// unready immediately and removes it from Service endpoint rotation
// while the existing drain sequence still has time to run.
func (h *Handler) SetDraining(draining bool) {
	h.draining.Store(draining)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusOK)
	case "/readyz":
		h.serveReadyz(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveReadyz(w http.ResponseWriter, r *http.Request) {
	if h.draining.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	if h.pinger != nil {
		ctx, cancel := context.WithTimeout(r.Context(), pingTimeout)
		defer cancel()
		if err := h.pinger(ctx); err != nil {
			http.Error(w, "dependency unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}
