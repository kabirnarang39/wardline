package usecase

import (
	"fmt"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// tenantWindowState is one tenant's aggregate call-volume baseline: the
// sum of every identity's traffic under that tenant, per window. See
// domain.TenantAnomalyConfig's doc comment for why this exists and why
// it only ever logs, never blocks.
//
// windowStart/cur/prev rotate on the tenant's own schedule (its first
// call ever, then every WindowSeconds), independent of any single
// identity's window -- there is no single identity whose window this
// could piggyback on.
type tenantWindowState struct {
	windowStart time.Time
	cur         int
	prev        int
	rateStat    onlineStat
	flagged     bool
	lastSeen    time.Time
}

// checkTenantDrift accumulates e into the tenant's aggregate window and,
// once that window completes, scores the just-completed window's total
// against the tenant's own running baseline via the same zCount floor
// checkDrift/checkMLScore use. Called unconditionally from
// recordAndCheck (under d.mu) whenever TenantAnomaly.Enabled -- unlike
// the per-identity checks, this has no windowJustCompleted precondition
// from the caller, since the tenant's window boundary is independent of
// the identity's.
// e.Decision == "blocked" is already filtered out by recordAndCheck's
// own guard before this is ever called -- no second check needed here.
func (d *Detector) checkTenantDrift(e auditdomain.Entry) *domain.Anomaly {
	if d.tenantState == nil {
		d.tenantState = make(map[string]*tenantWindowState)
	}
	window := time.Duration(d.cfg.WindowSeconds) * time.Second
	now := d.now()
	ts, ok := d.tenantState[e.Tenant]
	if !ok {
		// Truncate, not now() directly: every replica must agree on the
		// same window boundaries for the same real-world time period,
		// regardless of when each individually first saw this tenant's
		// traffic -- otherwise two replicas' windows never align and a
		// Postgres-backed cross-replica merge (tenantWindowStorePg
		// below) would silently merge nothing, each replica writing to
		// a different (tenant, window_start) row for what should be the
		// same window. See docs/superpowers/specs/2026-08-12-tenant-
		// anomaly-ha-design.md.
		ts = &tenantWindowState{windowStart: now.Truncate(window)}
		d.tenantState[e.Tenant] = ts
	}
	ts.lastSeen = now

	var anomaly *domain.Anomaly
	if now.Sub(ts.windowStart) >= window {
		finishedWindowStart := ts.windowStart
		localTotal := ts.cur
		ts.prev, ts.cur = localTotal, 0
		ts.windowStart = now.Truncate(window)
		ts.flagged = false

		// mergedTotal is what gets scored AND folded into the baseline
		// -- NEVER localTotal directly once tenantWindowStorePg is
		// configured. This is the correctness property the whole HA
		// design depends on: every replica must fold the SAME
		// cross-replica value into its own baseline, or baselines
		// silently diverge from what they're being compared against
		// (a baseline built from one replica's own slice of traffic
		// compared against a fully-merged current total would make
		// every window look inflated, regardless of real attack
		// activity). Do not "simplify" this by folding localTotal --
		// see the design spec's "key correctness property" section.
		mergedTotal := localTotal
		if d.tenantWindowStorePg != nil {
			merged, err := d.tenantWindowStorePg.AddAndGet(e.Tenant, finishedWindowStart, localTotal)
			if err != nil {
				if d.onError != nil {
					d.onError(fmt.Errorf("tenant_anomaly: failed to merge cross-replica window total, scoring this replica's own local total only this window: %w", err))
				}
				// Fail open on the scoring side too: fall back to
				// localTotal (mergedTotal already holds it) rather than
				// skipping this window's scoring entirely, matching
				// this codebase's established "degrade, don't go dark"
				// posture for a Postgres query failure.
			} else {
				mergedTotal = merged
			}
		}

		if mergedTotal >= d.cfg.TenantAnomaly.MinCalls {
			// AggregateZScore, not zCount -- see its own doc comment for
			// why zCount's relative floor is wrong at this scale.
			z := ts.rateStat.AggregateZScore(float64(mergedTotal))
			anomalous := z > d.cfg.TenantAnomaly.RateMultiplier
			if !anomalous {
				ts.rateStat.Update(float64(mergedTotal))
			} else {
				score := z
				anomaly = &domain.Anomaly{
					Timestamp: now,
					Tenant:    e.Tenant,
					Kind:      domain.KindTenantDrift,
					Detail: fmt.Sprintf(
						"tenant-aggregate call volume %d this window scored z=%.2f against its own baseline (threshold %.2f) -- a coordinated shift across identities in this tenant, invisible to any single per-identity heuristic",
						mergedTotal, z, d.cfg.TenantAnomaly.RateMultiplier),
					Score: &score,
				}
			}
		}
	}
	ts.cur++
	return anomaly
}
