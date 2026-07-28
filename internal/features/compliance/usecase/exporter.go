package usecase

import (
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/features/compliance/domain"
)

// BuildManifest aggregates auditEntries and anomalies into a
// domain.Manifest -- pure counting/histogramming, no I/O of its own.
func BuildManifest(
	version string,
	from, to, generatedAt time.Time,
	features map[string]bool,
	auditEntries []auditdomain.Entry,
	skippedAuditLines int,
	anomalies []anomalydomain.Anomaly,
) domain.Manifest {
	decisionCounts := make(map[string]int)
	for _, e := range auditEntries {
		decisionCounts[e.Decision]++
	}
	kindCounts := make(map[string]int)
	for _, a := range anomalies {
		kindCounts[string(a.Kind)]++
	}
	return domain.Manifest{
		WardlineVersion:             version,
		GeneratedAt:                 generatedAt,
		RangeFrom:                   from,
		RangeTo:                     to,
		Features:                    features,
		AuditEntryCount:             len(auditEntries),
		AuditDecisionCounts:         decisionCounts,
		UnparsableAuditLinesSkipped: skippedAuditLines,
		AnomalyEntryCount:           len(anomalies),
		AnomalyKindCounts:           kindCounts,
	}
}
