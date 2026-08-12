package usecase

import (
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

// Aggregate groups anomalies whose Timestamp falls in [windowStart,
// windowEnd) by (tenant, fingerprint, kind), producing one
// AnomalySummary per group with Count set to how many anomalies
// matched. Tenant joins the grouping key (not just riding along on the
// output) so two different tenants' identically-named identities --
// which hash to the SAME fingerprint, since Fingerprint is identity-only
// -- are never folded into one summary; see AnomalySummary's own doc
// comment. anomalies outside the window are silently excluded --
// Publisher is expected to pass only entries it intends to summarize for
// this window, but the boundary check is enforced here too so a caller
// mistake fails safe (fewer summaries, never a summary attributed to the
// wrong window).
func Aggregate(anomalies []anomalydomain.Anomaly, sharedSecret []byte, windowStart, windowEnd time.Time) []domain.AnomalySummary {
	type key struct {
		tenant      string
		fingerprint string
		kind        anomalydomain.Kind
	}
	counts := make(map[key]int)
	order := make([]key, 0)

	for _, a := range anomalies {
		if a.Timestamp.Before(windowStart) || !a.Timestamp.Before(windowEnd) {
			continue
		}
		k := key{tenant: a.Tenant, fingerprint: domain.Fingerprint(a.Identity, sharedSecret), kind: a.Kind}
		if _, seen := counts[k]; !seen {
			order = append(order, k)
		}
		counts[k]++
	}

	summaries := make([]domain.AnomalySummary, 0, len(order))
	for _, k := range order {
		summaries = append(summaries, domain.AnomalySummary{
			Fingerprint: k.fingerprint,
			Tenant:      k.tenant,
			Kind:        k.kind,
			Count:       counts[k],
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
		})
	}
	return summaries
}
