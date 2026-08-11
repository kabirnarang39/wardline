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

	// churnCUSUM is IdentityChurnConfig.CUSUMEnabled's own running
	// one-sided CUSUM accumulator over this tenant's per-window churn
	// count -- see cusumStep. Independent of drift_detection's
	// identityState.driftCUSUM (different scale: per-tenant, not
	// per-identity) and of rateStat above (rateStat is the baseline z_t
	// is scored against; churnCUSUM is what accumulates z_t over time).
	churnCUSUM float64
}

// ChurnBaselineSnapshot is identity_churn's own restart-persistence
// shape -- deliberately not OnlineStatSnapshot (which
// PostgresTenantBaselineStore already uses for tenant_anomaly): the
// extra CUSUM field is churn-specific and would be dead, always-zero
// weight on every tenant_anomaly row if the two types were shared.
type ChurnBaselineSnapshot struct {
	Mean  float64
	M2    float64
	Count int64
	CUSUM float64
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
// Cross-replica merge mirrors checkTenantDrift's own "fold the merged
// total, not the local delta" correctness property exactly (see
// docs/superpowers/specs/2026-08-12-tenant-anomaly-ha-design.md) --
// every replica must score AND fold the SAME cross-replica total, or
// baselines silently diverge from what they're compared against.
//
// Two independent decision rules run over the same merged total, same
// relationship checkMLScore's per-window zRate and checkDrift's CUSUM
// have for call_rate: an abrupt burst crosses RateMultiplier in one
// window (existing per-window test, unchanged); a slow trickle -- one
// disposable identity every many windows, individually always below
// RateMultiplier -- never crosses that test but still accumulates in
// churnCUSUM until it crosses H, when IdentityChurnConfig.CUSUMEnabled.
// This is the "future CUSUM-over-churn-count extension" the design
// doc's "out of scope" section named as the next step, built with the
// exact same cusumStep mechanics drift_detection already uses, not new
// machinery.
func (d *Detector) checkIdentityChurn(tenant string, now time.Time) *domain.Anomaly {
	if d.churnState == nil {
		d.churnState = make(map[string]*churnWindowState)
	}
	window := time.Duration(d.cfg.WindowSeconds) * time.Second
	cs, ok := d.churnState[tenant]
	if !ok {
		// Truncate, not now() directly -- same epoch-alignment reasoning
		// tenantWindowState's own doc comment gives: every replica must
		// agree on the same window boundaries for the same real-world
		// period, or a Postgres-backed cross-replica merge
		// (churnWindowStorePg below) would silently merge nothing.
		cs = &churnWindowState{windowStart: now.Truncate(window)}
		d.churnState[tenant] = cs
	}
	cs.lastSeen = now

	var anomaly *domain.Anomaly
	if now.Sub(cs.windowStart) >= window {
		finishedWindowStart := cs.windowStart
		localTotal := cs.cur
		cs.cur = 0
		cs.windowStart = now.Truncate(window)

		// mergedTotal is what gets scored AND folded into the baseline
		// -- NEVER localTotal directly once churnWindowStorePg is
		// configured. See checkIdentityChurn's own doc comment and
		// checkTenantDrift's "key correctness property" for why folding
		// localTotal instead would silently corrupt the comparison.
		mergedTotal := localTotal
		if d.churnWindowStorePg != nil {
			merged, err := d.churnWindowStorePg.AddAndGet(tenant, finishedWindowStart, localTotal)
			if err != nil {
				if d.onError != nil {
					d.onError(fmt.Errorf("identity_churn: failed to merge cross-replica window total, scoring this replica's own local total only this window: %w", err))
				}
				// Fail open on the scoring side too: fall back to
				// localTotal (mergedTotal already holds it) rather than
				// skipping this window's scoring entirely.
			} else {
				mergedTotal = merged
			}
		}

		if mergedTotal >= d.cfg.IdentityChurn.MinNewIdentities {
			z := cs.rateStat.AggregateZScore(float64(mergedTotal))
			anomalous := z > d.cfg.IdentityChurn.RateMultiplier
			if anomalous {
				score := z
				anomaly = &domain.Anomaly{
					Timestamp: now,
					Tenant:    tenant,
					Kind:      domain.KindIdentityChurn,
					Detail: fmt.Sprintf(
						"%d never-before-seen identities appeared in this tenant this window, scored z=%.2f against its own baseline (threshold %.2f) -- a burst of disposable identities, the fingerprint of an attacker discarding identities caught by per-identity heuristics (rate_spike, novel_tool, ml_score, drift_detection's h_jitter_fraction) and retrying fresh ones",
						mergedTotal, z, d.cfg.IdentityChurn.RateMultiplier),
					Score: &score,
				}
			} else {
				cs.rateStat.Update(float64(mergedTotal))
				// CUSUM only evaluated on a non-abrupt window -- an
				// already-reported abrupt burst has nothing further to
				// accumulate toward this same tick, same as
				// checkDriftFeature's own post-alarm reset posture.
				if d.cfg.IdentityChurn.CUSUMEnabled {
					if fired, alarmed := cusumStep(&cs.churnCUSUM, z, d.cfg.IdentityChurn.K, d.cfg.IdentityChurn.H); alarmed {
						score := fired
						anomaly = &domain.Anomaly{
							Timestamp: now,
							Tenant:    tenant,
							Kind:      domain.KindIdentityChurn,
							Detail: fmt.Sprintf(
								"cumulative sustained rise in new-identity churn (cusum %.2f) exceeded decision threshold %.2f -- a slow trickle of disposable identities, individually below any single window's rate_multiplier, adding up over time the same way drift_detection's call_rate CUSUM catches a slow ramp",
								fired, d.cfg.IdentityChurn.H),
							Score: &score,
						}
					}
				}
			}
		}
	}
	cs.cur++
	return anomaly
}
