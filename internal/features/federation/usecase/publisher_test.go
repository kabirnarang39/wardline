package usecase_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/usecase"
)

type fakeAlertReader struct {
	anomalies []anomalydomain.Anomaly
}

func (f *fakeAlertReader) Since(afterID int64) []anomalydomain.Anomaly {
	return f.anomalies
}

type fakeSender struct {
	mu      sync.Mutex
	sent    []domain.SignedSummaryBatch
	sendErr map[string]error // keyed by peer endpoint
}

func (f *fakeSender) Send(ctx context.Context, endpoint string, batch domain.SignedSummaryBatch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.sendErr[endpoint]; ok {
		return err
	}
	f.sent = append(f.sent, batch)
	return nil
}

func testSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestPublisher_PublishOnce_SendsToEveryPeer(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	reader := &fakeAlertReader{anomalies: []anomalydomain.Anomaly{
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: now.Add(-10 * time.Second)},
	}}
	sender := &fakeSender{sendErr: map[string]error{}}
	peers := []domain.Peer{
		{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"},
		{ID: "us-cluster", Endpoint: "https://us.example.com/federation/summaries"},
	}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60, func() time.Time { return now })

	errs := p.PublishOnce(context.Background(), now)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 2 {
		t.Fatalf("expected 2 sent batches (one per peer), got %d", len(sender.sent))
	}
	for _, batch := range sender.sent {
		if batch.InstanceID != "local-instance" {
			t.Errorf("expected InstanceID local-instance, got %q", batch.InstanceID)
		}
		if len(batch.Summaries) != 1 {
			t.Errorf("expected 1 summary in batch, got %d", len(batch.Summaries))
		}
		if len(batch.Signature) == 0 {
			t.Error("expected a non-empty signature")
		}
	}
}

func TestPublisher_OnePeerFails_OthersStillSucceed(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	reader := &fakeAlertReader{anomalies: []anomalydomain.Anomaly{
		{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: now.Add(-10 * time.Second)},
	}}
	sender := &fakeSender{sendErr: map[string]error{
		"https://eu.example.com/federation/summaries": errors.New("connection refused"),
	}}
	peers := []domain.Peer{
		{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"},
		{ID: "us-cluster", Endpoint: "https://us.example.com/federation/summaries"},
	}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60, func() time.Time { return now })

	errs := p.PublishOnce(context.Background(), now)
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error (from eu-cluster), got %d: %v", len(errs), errs)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 1 {
		t.Fatalf("expected us-cluster to still receive its batch, got %d sent", len(sender.sent))
	}
}

func TestPublisher_NoAnomalies_SendsNothing(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	reader := &fakeAlertReader{anomalies: nil}
	sender := &fakeSender{sendErr: map[string]error{}}
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"}}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60, func() time.Time { return now })

	errs := p.PublishOnce(context.Background(), now)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 0 {
		t.Fatalf("expected nothing sent when there are no local anomalies, got %d", len(sender.sent))
	}
}
