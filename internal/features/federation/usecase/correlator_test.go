package usecase_test

import (
	"sync"
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/usecase"
)

func TestCorrelator_MinInstancesReached_EmitsOneAlert(t *testing.T) {
	var mu sync.Mutex
	var alerts []domain.CorrelatedAlert
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 2, CorrelationWindowSeconds: 300},
		func(a domain.CorrelatedAlert) {
			mu.Lock()
			defer mu.Unlock()
			alerts = append(alerts, a)
		},
		func() time.Time { return now },
	)

	summary := domain.AnomalySummary{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, Count: 5, WindowStart: now, WindowEnd: now.Add(time.Minute)}

	c.Ingest("instance-a", summary)
	mu.Lock()
	if len(alerts) != 0 {
		t.Fatalf("expected no alert after only 1 instance, got %d", len(alerts))
	}
	mu.Unlock()

	c.Ingest("instance-b", summary)
	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 alert after 2nd distinct instance, got %d", len(alerts))
	}
	if len(alerts[0].InstanceIDs) != 2 {
		t.Errorf("expected 2 instance IDs, got %v", alerts[0].InstanceIDs)
	}
}

func TestCorrelator_SameInstanceTwice_DoesNotCountAsTwoDistinct(t *testing.T) {
	var mu sync.Mutex
	var alerts []domain.CorrelatedAlert
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 2, CorrelationWindowSeconds: 300},
		func(a domain.CorrelatedAlert) {
			mu.Lock()
			defer mu.Unlock()
			alerts = append(alerts, a)
		},
		func() time.Time { return now },
	)

	summary := domain.AnomalySummary{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, Count: 5, WindowStart: now, WindowEnd: now.Add(time.Minute)}

	c.Ingest("instance-a", summary)
	c.Ingest("instance-a", summary)

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 0 {
		t.Fatalf("expected no alert -- same instance reporting twice is not 2 distinct instances, got %d", len(alerts))
	}
}

func TestCorrelator_DedupLatch_OnlyOneAlertPerFingerprintPerWindow(t *testing.T) {
	var mu sync.Mutex
	var alerts []domain.CorrelatedAlert
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 2, CorrelationWindowSeconds: 300},
		func(a domain.CorrelatedAlert) {
			mu.Lock()
			defer mu.Unlock()
			alerts = append(alerts, a)
		},
		func() time.Time { return now },
	)

	summary := domain.AnomalySummary{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, Count: 5, WindowStart: now, WindowEnd: now.Add(time.Minute)}

	c.Ingest("instance-a", summary)
	c.Ingest("instance-b", summary)
	c.Ingest("instance-c", summary) // a 3rd instance sighting the same fingerprint/kind

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 alert despite 3 sightings -- dedup latch should suppress repeats, got %d", len(alerts))
	}
}

func TestCorrelator_DifferentFingerprints_NeverMerge(t *testing.T) {
	var mu sync.Mutex
	var alerts []domain.CorrelatedAlert
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 2, CorrelationWindowSeconds: 300},
		func(a domain.CorrelatedAlert) {
			mu.Lock()
			defer mu.Unlock()
			alerts = append(alerts, a)
		},
		func() time.Time { return now },
	)

	c.Ingest("instance-a", domain.AnomalySummary{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, Count: 1, WindowStart: now, WindowEnd: now.Add(time.Minute)})
	c.Ingest("instance-b", domain.AnomalySummary{Fingerprint: "fp2", Kind: anomalydomain.KindRateSpike, Count: 1, WindowStart: now, WindowEnd: now.Add(time.Minute)})

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 0 {
		t.Fatalf("expected no alert -- 2 different fingerprints from 2 instances is not correlation, got %d", len(alerts))
	}
}
