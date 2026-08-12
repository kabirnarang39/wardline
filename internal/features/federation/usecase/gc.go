package usecase

import (
	"time"

	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// GCCorrelatorOnce drops every (tenant, fingerprint, kind) state whose
// every instance sighting is older than 2x interval before now. Exported
// (not a method) and taking now explicitly, purely so tests can drive it
// deterministically -- StartCorrelatorGC below is the real production
// entry point. Dropping state is safe: the (tenant, fingerprint) pair
// simply looks fresh again on its next sighting, same conservative
// posture as anomaly detection's own identityState GC.
func GCCorrelatorOnce(c *Correlator, now time.Time, interval time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-2 * interval)
	for stateKey, byKind := range c.state {
		for kind, st := range byKind {
			stillFresh := false
			for _, seen := range st.instances {
				if seen.After(cutoff) {
					stillFresh = true
					break
				}
			}
			if !stillFresh {
				delete(byKind, kind)
			}
		}
		if len(byKind) == 0 {
			delete(c.state, stateKey)
		}
	}
}

// CorrelatorHasFingerprint reports whether the correlator currently
// holds any state for (tenantName, fingerprint), for any kind. Test-only
// helper.
func CorrelatorHasFingerprint(c *Correlator, tenantName, fingerprint string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.state[tenant.Key(tenantName, fingerprint)]
	return ok
}

// StartCorrelatorGC runs GCCorrelatorOnce on a ticker until stop is
// closed. Intended to be launched in its own goroutine by the
// composition root (cmd/wardline/main.go), which owns closing stop on
// shutdown -- same shape as anomaly/usecase.StartGC.
func StartCorrelatorGC(c *Correlator, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			GCCorrelatorOnce(c, now, interval)
		}
	}
}
