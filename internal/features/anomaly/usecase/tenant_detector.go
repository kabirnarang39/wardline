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
	ts, ok := d.tenantState[e.Tenant]
	if !ok {
		ts = &tenantWindowState{windowStart: d.now()}
		d.tenantState[e.Tenant] = ts
	}
	ts.lastSeen = d.now()

	now := d.now()
	window := time.Duration(d.cfg.WindowSeconds) * time.Second
	var anomaly *domain.Anomaly
	if now.Sub(ts.windowStart) >= window {
		total := ts.cur
		ts.prev, ts.cur = total, 0
		ts.windowStart = now
		ts.flagged = false

		if total >= d.cfg.TenantAnomaly.MinCalls {
			// AggregateZScore, not zCount -- see its own doc comment for
			// why zCount's relative floor is wrong at this scale.
			z := ts.rateStat.AggregateZScore(float64(total))
			anomalous := z > d.cfg.TenantAnomaly.RateMultiplier
			if !anomalous {
				ts.rateStat.Update(float64(total))
			} else {
				score := z
				anomaly = &domain.Anomaly{
					Timestamp: now,
					Tenant:    e.Tenant,
					Kind:      domain.KindTenantDrift,
					Detail: fmt.Sprintf(
						"tenant-aggregate call volume %d this window scored z=%.2f against its own baseline (threshold %.2f) -- a coordinated shift across identities in this tenant, invisible to any single per-identity heuristic",
						total, z, d.cfg.TenantAnomaly.RateMultiplier),
					Score: &score,
				}
			}
		}
	}
	ts.cur++
	return anomaly
}
