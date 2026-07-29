package usecase_test

import (
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/usecase"
)

func TestAggregate_GroupsSameFingerprintAndKind(t *testing.T) {
	secret := []byte("secret")
	start := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)

	anomalies := []anomalydomain.Anomaly{
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(10 * time.Second)},
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(20 * time.Second)},
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(30 * time.Second)},
	}

	summaries := usecase.Aggregate(anomalies, secret, start, end)

	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d: %+v", len(summaries), summaries)
	}
	want := domain.Fingerprint("agent-abc123", secret)
	if summaries[0].Fingerprint != want {
		t.Errorf("expected fingerprint %q, got %q", want, summaries[0].Fingerprint)
	}
	if summaries[0].Kind != anomalydomain.KindRateSpike {
		t.Errorf("expected kind rate_spike, got %q", summaries[0].Kind)
	}
	if summaries[0].Count != 3 {
		t.Errorf("expected count 3, got %d", summaries[0].Count)
	}
	if !summaries[0].WindowStart.Equal(start) || !summaries[0].WindowEnd.Equal(end) {
		t.Errorf("expected window [%v, %v], got [%v, %v]", start, end, summaries[0].WindowStart, summaries[0].WindowEnd)
	}
}

func TestAggregate_DifferentFingerprintsNeverMerge(t *testing.T) {
	secret := []byte("secret")
	start := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)

	anomalies := []anomalydomain.Anomaly{
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(10 * time.Second)},
		{Identity: "agent-xyz789", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(10 * time.Second)},
	}

	summaries := usecase.Aggregate(anomalies, secret, start, end)

	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries for 2 distinct identities, got %d: %+v", len(summaries), summaries)
	}
}

func TestAggregate_DifferentKindsNeverMerge(t *testing.T) {
	secret := []byte("secret")
	start := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)

	anomalies := []anomalydomain.Anomaly{
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(10 * time.Second)},
		{Identity: "agent-abc123", Kind: anomalydomain.KindNovelTool, Timestamp: start.Add(10 * time.Second)},
	}

	summaries := usecase.Aggregate(anomalies, secret, start, end)

	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries for 2 distinct kinds, got %d: %+v", len(summaries), summaries)
	}
}

func TestAggregate_EntriesOutsideWindowExcluded(t *testing.T) {
	secret := []byte("secret")
	start := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)

	anomalies := []anomalydomain.Anomaly{
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(-time.Second)},     // before window
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: end.Add(time.Second)},        // after window
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: end},                         // exactly at windowEnd -- must be excluded, window is a half-open [windowStart, windowEnd) interval
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: start.Add(30 * time.Second)}, // inside
	}

	summaries := usecase.Aggregate(anomalies, secret, start, end)

	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (only the in-window entry), got %d: %+v", len(summaries), summaries)
	}
	if summaries[0].Count != 1 {
		t.Errorf("expected count 1, got %d", summaries[0].Count)
	}
}

func TestAggregate_EmptyInput_EmptyOutput(t *testing.T) {
	secret := []byte("secret")
	start := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)

	summaries := usecase.Aggregate(nil, secret, start, end)

	if len(summaries) != 0 {
		t.Fatalf("expected 0 summaries for empty input, got %d", len(summaries))
	}
}
