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

func TestCorrelator_ReArmsAfterWindowElapses_UnderSustainedCondition(t *testing.T) {
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

	mu.Lock()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 alert after the first correlated sighting, got %d", len(alerts))
	}
	mu.Unlock()

	// Sustained condition: the same fingerprint keeps getting sighted by
	// both instances well past the correlation window -- the dedup latch
	// must re-arm and fire again, not stay latched for the state's whole
	// lifetime (that would mean a sustained cross-instance attack alerts
	// exactly once, ever).
	now = now.Add(301 * time.Second) // > 1 full window past the last alert
	c.Ingest("instance-a", summary)
	c.Ingest("instance-b", summary)

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 2 {
		t.Fatalf("expected a 2nd alert once a full window elapsed under a sustained condition, got %d", len(alerts))
	}
}

func TestCorrelator_DoesNotReArmBeforeWindowElapses(t *testing.T) {
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

	now = now.Add(100 * time.Second) // well within the 300s window
	c.Ingest("instance-a", summary)
	c.Ingest("instance-b", summary)

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 1 {
		t.Fatalf("expected still exactly 1 alert before a full window has elapsed, got %d", len(alerts))
	}
}

func TestCorrelator_EmittedAlert_InstanceIDsSortedAndFirstSeenIsEarliestSighting(t *testing.T) {
	var mu sync.Mutex
	var alerts []domain.CorrelatedAlert
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

	c := usecase.NewCorrelator(
		domain.FederationConfig{MinInstancesForCorrelation: 3, CorrelationWindowSeconds: 300},
		func(a domain.CorrelatedAlert) {
			mu.Lock()
			defer mu.Unlock()
			alerts = append(alerts, a)
		},
		func() time.Time { return now },
	)

	summary := domain.AnomalySummary{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, Count: 5, WindowStart: now, WindowEnd: now.Add(time.Minute)}

	firstSightingTime := now
	c.Ingest("us-cluster", summary) // deliberately out of alphabetical order
	now = now.Add(10 * time.Second)
	c.Ingest("ap-cluster", summary)
	now = now.Add(10 * time.Second)
	c.Ingest("eu-cluster", summary)

	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly 1 alert, got %d", len(alerts))
	}
	want := []string{"ap-cluster", "eu-cluster", "us-cluster"}
	got := alerts[0].InstanceIDs
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected sorted InstanceIDs %v, got %v", want, got)
		}
	}
	if !alerts[0].FirstSeen.Equal(firstSightingTime) {
		t.Fatalf("expected FirstSeen to be the earliest real sighting %v, got %v", firstSightingTime, alerts[0].FirstSeen)
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
