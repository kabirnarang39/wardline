package usecase_test

import (
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/usecase"
)

func TestCorrelatorGC_DropsStateOlderThan2xInterval(t *testing.T) {
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 99, CorrelationWindowSeconds: 300},
		func(domain.CorrelatedAlert) {},
		func() time.Time { return current },
	)

	c.Ingest("instance-a", domain.AnomalySummary{Fingerprint: "old-fp", Kind: anomalydomain.KindRateSpike, Count: 1, WindowStart: current, WindowEnd: current.Add(time.Minute)})

	interval := 10 * time.Minute
	current = current.Add(21 * time.Minute) // > 2x interval later
	usecase.GCCorrelatorOnce(c, current, interval)

	if usecase.CorrelatorHasFingerprint(c, "old-fp") {
		t.Fatal("expected old-fp state to be dropped after 2x interval with no new sightings")
	}
}

func TestCorrelatorGC_KeepsRecentState(t *testing.T) {
	current := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 99, CorrelationWindowSeconds: 300},
		func(domain.CorrelatedAlert) {},
		func() time.Time { return current },
	)

	c.Ingest("instance-a", domain.AnomalySummary{Fingerprint: "fresh-fp", Kind: anomalydomain.KindRateSpike, Count: 1, WindowStart: current, WindowEnd: current.Add(time.Minute)})

	interval := 10 * time.Minute
	current = current.Add(5 * time.Minute) // well within 2x interval
	usecase.GCCorrelatorOnce(c, current, interval)

	if !usecase.CorrelatorHasFingerprint(c, "fresh-fp") {
		t.Fatal("expected fresh-fp state to survive a GC tick within 2x interval")
	}
}
