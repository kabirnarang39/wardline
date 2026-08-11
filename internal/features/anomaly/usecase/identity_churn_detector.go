package usecase

import (
	"fmt"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
)

// churnWindowState is one tenant's new-identity-count baseline: how
// many identities were seen for the very first time within a window,
// summed across every identity newly appearing under that tenant. See
// domain.IdentityChurnConfig's doc comment for why this exists and why
// it only ever logs, never blocks.
//
// Deliberately a separate map/struct from tenantWindowState
// (tenant_anomaly's own), not a shared one: call-volume totals and
// new-identity counts are different metrics with different
// false-positive shapes (a tenant's call volume swings far more from
// one window to the next than its new-identity rate normally does), and
// coupling them into one struct/config would make both harder to tune
// independently.
type churnWindowState struct {
	windowStart time.Time
	cur         int
	rateStat    onlineStat
	lastSeen    time.Time
}

// checkIdentityChurn accumulates one first-sighting into tenant's
// churn window and, once that window completes, scores the
// just-completed window's new-identity count against the tenant's own
// running baseline via AggregateZScore -- the same z-scoring
// checkTenantDrift uses, for the same reason (a per-identity-scale
// relative floor is wrong once the value being scored is itself an
// aggregate across many identities). Called from recordAndCheck (under
// d.mu) only when this Publish call's identity is a genuine first
// sighting -- see recordAndCheck's own call site for exactly where
// "first sighting" is determined, immediately adjacent to the existing
// d.state lookup so it reads the exact same state check the rest of
// Publish already does, not a second pass.
//
// No cross-replica merge this cycle (see
// docs/superpowers/specs/2026-08-12-identity-churn-design.md's "scope"
// section) -- this is a direct port of checkTenantDrift's own shape
// before its own HA extension added the merge step, kept that simple
// deliberately rather than half-wiring a Postgres dependency this
// cycle doesn't need yet.
func (d *Detector) checkIdentityChurn(tenant string, now time.Time) *domain.Anomaly {
	if d.churnState == nil {
		d.churnState = make(map[string]*churnWindowState)
	}
	window := time.Duration(d.cfg.WindowSeconds) * time.Second
	cs, ok := d.churnState[tenant]
	if !ok {
		// Truncate, not now() directly -- same epoch-alignment reasoning
		// tenantWindowState's own doc comment gives: a future HA
		// extension of this feature needs every replica to agree on the
		// same window boundaries, and there is no reason to repeat the
		// bug tenant_anomaly's own Task 1 already found and fixed by
		// building this state fresh without it.
		cs = &churnWindowState{windowStart: now.Truncate(window)}
		d.churnState[tenant] = cs
	}
	cs.lastSeen = now

	var anomaly *domain.Anomaly
	if now.Sub(cs.windowStart) >= window {
		total := cs.cur
		cs.cur = 0
		cs.windowStart = now.Truncate(window)

		if total >= d.cfg.IdentityChurn.MinNewIdentities {
			z := cs.rateStat.AggregateZScore(float64(total))
			anomalous := z > d.cfg.IdentityChurn.RateMultiplier
			if !anomalous {
				cs.rateStat.Update(float64(total))
			} else {
				score := z
				anomaly = &domain.Anomaly{
					Timestamp: now,
					Tenant:    tenant,
					Kind:      domain.KindIdentityChurn,
					Detail: fmt.Sprintf(
						"%d never-before-seen identities appeared in this tenant this window, scored z=%.2f against its own baseline (threshold %.2f) -- a burst of disposable identities, the fingerprint of an attacker discarding identities caught by per-identity heuristics (rate_spike, novel_tool, ml_score, drift_detection's h_jitter_fraction) and retrying fresh ones",
						total, z, d.cfg.IdentityChurn.RateMultiplier),
					Score: &score,
				}
			}
		}
	}
	cs.cur++
	return anomaly
}
