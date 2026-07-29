package usecase

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

// AlertReader is the subset of anomaly/usecase.AlertBuffer's behavior
// Publisher depends on -- the only thing federation imports from the
// anomaly feature besides the plain anomalydomain.Kind const type. A
// narrow interface, matching every other *Source pattern already used
// across this codebase (dashboard's AuditSource/AnomalySource, etc.).
// Returns anomalyusecase.Alert (not plain anomalydomain.Anomaly) because
// each Alert's ID is what lets PublishOnce advance its read cursor --
// afterID=0, limit=0 mean "from the start"/"no cap", matching
// AlertBuffer.Since's own semantics.
type AlertReader interface {
	Since(afterID int64, limit int) []anomalyusecase.Alert
}

// batchSigner abstracts signing so Publisher's own tests don't need a
// real RSA key beyond what testSigningKey generates; the real Sign
// function (Task 5) satisfies this trivially since Publisher calls it
// directly, not through an interface -- kept as a plain function
// reference for simplicity (there's only ever one signing algorithm,
// unlike policy backends, so this isn't a place Open/Closed applies).
type signFunc func(payload []byte, key *rsa.PrivateKey) ([]byte, error)

// BatchSender delivers one SignedSummaryBatch to one peer endpoint.
// adapter.HTTPSender (Task 7 adapter half) is the real implementation;
// tests supply a fake.
type BatchSender interface {
	Send(ctx context.Context, endpoint string, batch domain.SignedSummaryBatch) error
}

// Publisher periodically aggregates this instance's local anomalies
// into pseudonymized summaries and pushes a signed batch to every
// configured peer. A failed send to one peer is logged and skipped --
// it never blocks or affects delivery to any other peer, and never
// blocks or affects local anomaly detection itself.
type Publisher struct {
	instanceID   string
	reader       AlertReader
	peers        []domain.Peer
	signingKey   *rsa.PrivateKey
	sharedSecret []byte
	sender       BatchSender
	sign         signFunc
	lastReadID   int64
	windowSecs   int
	now          func() time.Time
}

func NewPublisher(instanceID string, reader AlertReader, peers []domain.Peer, signingKey *rsa.PrivateKey, sharedSecret []byte, sender BatchSender, windowSeconds int, now func() time.Time) *Publisher {
	return &Publisher{
		instanceID:   instanceID,
		reader:       reader,
		peers:        peers,
		signingKey:   signingKey,
		sharedSecret: sharedSecret,
		sender:       sender,
		sign:         signPayload,
		windowSecs:   windowSeconds,
		now:          now,
	}
}

func rsaSignPSS(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
}

// signPayload is the production signFunc -- a package-level var so
// tests could override it if ever needed, but Task 5's real Sign
// (imported via the adapter package would create an import cycle, so
// this usecase re-declares the RSA-PSS call directly using only
// crypto/rsa, matching Sign's implementation exactly) is called here.
// Kept intentionally tiny and duplicated rather than reaching into
// adapter from usecase, which would invert the dependency rule.
func signPayload(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	return rsaSignPSS(payload, key)
}

// PublishOnce aggregates every local anomaly since the last publish
// call into one window ending at now, and sends a signed batch to
// every configured peer. Returns one error per peer that failed to
// receive the batch (nil slice means every peer succeeded, including
// the trivial case of zero peers or zero anomalies to report).
func (p *Publisher) PublishOnce(ctx context.Context, now time.Time) []error {
	alerts := p.reader.Since(p.lastReadID, 0)
	if len(alerts) == 0 {
		return nil
	}

	anomalies := make([]anomalydomain.Anomaly, len(alerts))
	var maxID int64
	for i, a := range alerts {
		anomalies[i] = a.Anomaly
		if a.ID > maxID {
			maxID = a.ID
		}
	}
	p.lastReadID = maxID

	windowStart := now.Add(-time.Duration(p.windowSecs) * time.Second)
	summaries := Aggregate(anomalies, p.sharedSecret, windowStart, now)
	if len(summaries) == 0 {
		return nil
	}

	batch := domain.SignedSummaryBatch{InstanceID: p.instanceID, Summaries: summaries}
	payload, err := json.Marshal(struct {
		InstanceID string                  `json:"instance_id"`
		Summaries  []domain.AnomalySummary `json:"summaries"`
	}{InstanceID: batch.InstanceID, Summaries: batch.Summaries})
	if err != nil {
		return []error{fmt.Errorf("marshal summary batch: %w", err)}
	}

	sig, err := p.sign(payload, p.signingKey)
	if err != nil {
		return []error{fmt.Errorf("sign summary batch: %w", err)}
	}
	batch.Signature = sig

	var errs []error
	for _, peer := range p.peers {
		if err := p.sender.Send(ctx, peer.Endpoint, batch); err != nil {
			errs = append(errs, fmt.Errorf("send to peer %s: %w", peer.ID, err))
		}
	}
	return errs
}

// StartPublisher runs PublishOnce on a ticker until stop is closed.
// Intended to be launched in its own goroutine by the composition root
// (cmd/wardline/main.go), which owns closing stop on shutdown -- same
// shape as anomaly/usecase.StartGC.
func StartPublisher(p *Publisher, interval time.Duration, stop <-chan struct{}, onError func([]error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			if errs := p.PublishOnce(context.Background(), now); len(errs) > 0 && onError != nil {
				onError(errs)
			}
		}
	}
}
