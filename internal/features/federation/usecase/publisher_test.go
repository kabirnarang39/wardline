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
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/usecase"
)

type fakeAlertReader struct {
	alerts []anomalyusecase.Alert
}

func (f *fakeAlertReader) Since(afterID int64, limit int) []anomalyusecase.Alert {
	var out []anomalyusecase.Alert
	for _, a := range f.alerts {
		if a.ID > afterID {
			out = append(out, a)
		}
	}
	return out
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
	reader := &fakeAlertReader{alerts: []anomalyusecase.Alert{
		{ID: 1, Anomaly: anomalydomain.Anomaly{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: now.Add(-10 * time.Second)}},
	}}
	sender := &fakeSender{sendErr: map[string]error{}}
	peers := []domain.Peer{
		{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"},
		{ID: "us-cluster", Endpoint: "https://us.example.com/federation/summaries"},
	}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60)

	summaries, errs := p.PublishOnce(context.Background(), now)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary returned, got %d", len(summaries))
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
	reader := &fakeAlertReader{alerts: []anomalyusecase.Alert{
		{ID: 1, Anomaly: anomalydomain.Anomaly{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: now.Add(-10 * time.Second)}},
	}}
	sender := &fakeSender{sendErr: map[string]error{
		"https://eu.example.com/federation/summaries": errors.New("connection refused"),
	}}
	peers := []domain.Peer{
		{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"},
		{ID: "us-cluster", Endpoint: "https://us.example.com/federation/summaries"},
	}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60)

	_, errs := p.PublishOnce(context.Background(), now)
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
	reader := &fakeAlertReader{alerts: nil}
	sender := &fakeSender{sendErr: map[string]error{}}
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"}}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60)

	summaries, errs := p.PublishOnce(context.Background(), now)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
	if len(summaries) != 0 {
		t.Fatalf("expected no summaries when there are no local anomalies, got %d", len(summaries))
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != 0 {
		t.Fatalf("expected nothing sent when there are no local anomalies, got %d", len(sender.sent))
	}
}

func TestPublisher_SecondPublishOnce_DoesNotResendAlreadyReadAnomalies(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	reader := &fakeAlertReader{alerts: []anomalyusecase.Alert{
		{ID: 1, Anomaly: anomalydomain.Anomaly{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: now.Add(-10 * time.Second)}},
	}}
	sender := &fakeSender{sendErr: map[string]error{}}
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"}}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60)

	if _, errs := p.PublishOnce(context.Background(), now); len(errs) != 0 {
		t.Fatalf("first PublishOnce: expected no errors, got %v", errs)
	}
	sender.mu.Lock()
	firstSent := len(sender.sent)
	sender.mu.Unlock()
	if firstSent != 1 {
		t.Fatalf("expected 1 batch sent on first call, got %d", firstSent)
	}

	// Same underlying anomaly is still within the aggregation window (60s)
	// on this second call a few seconds later, but it must not be
	// re-sent: PublishOnce's read cursor (lastReadID) should already
	// exclude it.
	second := now.Add(5 * time.Second)
	if _, errs := p.PublishOnce(context.Background(), second); len(errs) != 0 {
		t.Fatalf("second PublishOnce: expected no errors, got %v", errs)
	}

	sender.mu.Lock()
	defer sender.mu.Unlock()
	if len(sender.sent) != firstSent {
		t.Fatalf("expected no additional batches sent on second call, got %d total (was %d after first call)", len(sender.sent), firstSent)
	}
}

func TestStartPublisher_RunsATickThenStopsCleanlyOnStopClose(t *testing.T) {
	reader := &fakeAlertReader{alerts: []anomalyusecase.Alert{
		{ID: 1, Anomaly: anomalydomain.Anomaly{Identity: "agent-abc123", Kind: anomalydomain.KindRateSpike, Timestamp: time.Now()}},
	}}
	sender := &fakeSender{sendErr: map[string]error{}}
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com/federation/summaries"}}

	p := usecase.NewPublisher("local-instance", reader, peers, testSigningKey(t), []byte("shared-secret"), sender, 60)

	stop := make(chan struct{})
	tickCh := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		usecase.StartPublisher(p, 10*time.Millisecond, stop, func(summaries []domain.AnomalySummary) {
			select {
			case tickCh <- struct{}{}:
			default:
			}
		}, nil)
		close(done)
	}()

	select {
	case <-tickCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for StartPublisher's first tick")
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartPublisher did not return after stop was closed")
	}
}
