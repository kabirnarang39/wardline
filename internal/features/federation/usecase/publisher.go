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
// AlertBuffer.Since's own semantics. The tenantFilter parameter added to
// AlertBuffer.Since for dashboard tenant isolation (Task 23) is always
// passed as "" here -- Publisher aggregates every local tenant's
// anomalies into cross-instance summaries; per-tenant filtering of the
// federation view is an explicit future-cycle item, not this task's
// scope.
type AlertReader interface {
	Since(afterID int64, limit int, tenantFilter string) []anomalyusecase.Alert
}

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
	lastReadID   int64
	windowSecs   int
}

// NewPublisher does not take a now func() time.Time -- PublishOnce takes
// now as an explicit parameter instead (see its doc comment), so there
// is nothing here for a stored clock to do.
func NewPublisher(instanceID string, reader AlertReader, peers []domain.Peer, signingKey *rsa.PrivateKey, sharedSecret []byte, sender BatchSender, windowSeconds int) *Publisher {
	return &Publisher{
		instanceID:   instanceID,
		reader:       reader,
		peers:        peers,
		signingKey:   signingKey,
		sharedSecret: sharedSecret,
		sender:       sender,
		windowSecs:   windowSeconds,
	}
}

// rsaSignPSS is Publisher's real signing function -- RSA-PSS over
// sha256(payload), matching adapter.Sign exactly. Re-declared here
// (rather than importing the adapter package's Sign) to avoid an
// adapter-from-usecase import, which would invert the Clean Architecture
// dependency rule. Called directly from PublishOnce -- no interface or
// function-variable indirection around it: there is only ever one
// signing algorithm, and every test (including this package's own,
// which generate a real RSA key) exercises this exact call, so an
// abstraction layer here would have no real caller.
func rsaSignPSS(payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
}

// PublishOnce aggregates every local anomaly since the last publish
// call into one window ending at now, and sends a signed batch to
// every configured peer. Returns the summaries computed for this tick
// (nil when there was nothing to aggregate) alongside one error per
// peer that failed to receive the batch (nil slice means every peer
// succeeded, including the trivial case of zero peers or zero
// anomalies to report). Exposing the summaries lets a caller
// (cmd/wardline/main.go) feed this instance's own local detections into
// its Correlator using the exact same aggregation window Publisher just
// computed, instead of recomputing Aggregate a second time and risking
// the two windows drifting apart.
func (p *Publisher) PublishOnce(ctx context.Context, now time.Time) ([]domain.AnomalySummary, []error) {
	alerts := p.reader.Since(p.lastReadID, 0, "")
	if len(alerts) == 0 {
		return nil, nil
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

	// The cursor above (lastReadID) advances past every alert Since just
	// returned, regardless of how old it is -- Since has no time bound of
	// its own. windowStart normally trails now by windowSecs, but if this
	// tick is running late (e.g. a prior tick overran the publish interval
	// blocked on unreachable peers) some of what the cursor just consumed
	// can be older than that. Aggregate only keeps entries within
	// [windowStart, now), so without this adjustment anything the cursor
	// consumed but Aggregate excludes would be silently dropped forever --
	// extend windowStart backward to cover the earliest alert actually
	// read this tick, so nothing the cursor advances past is ever lost.
	windowStart := now.Add(-time.Duration(p.windowSecs) * time.Second)
	for _, a := range anomalies {
		if a.Timestamp.Before(windowStart) {
			windowStart = a.Timestamp
		}
	}
	summaries := Aggregate(anomalies, p.sharedSecret, windowStart, now)
	if len(summaries) == 0 {
		return nil, nil
	}

	batch := domain.SignedSummaryBatch{InstanceID: p.instanceID, Summaries: summaries}
	payload, err := json.Marshal(struct {
		InstanceID string                  `json:"instance_id"`
		Summaries  []domain.AnomalySummary `json:"summaries"`
	}{InstanceID: batch.InstanceID, Summaries: batch.Summaries})
	if err != nil {
		return summaries, []error{fmt.Errorf("marshal summary batch: %w", err)}
	}

	sig, err := rsaSignPSS(payload, p.signingKey)
	if err != nil {
		return summaries, []error{fmt.Errorf("sign summary batch: %w", err)}
	}
	batch.Signature = sig

	var errs []error
	for _, peer := range p.peers {
		if err := p.sender.Send(ctx, peer.Endpoint, batch); err != nil {
			errs = append(errs, fmt.Errorf("send to peer %s: %w", peer.ID, err))
		}
	}
	return summaries, errs
}

// StartPublisher runs PublishOnce on a ticker until stop is closed.
// Intended to be launched in its own goroutine by the composition root
// (cmd/wardline/main.go), which owns closing stop on shutdown -- same
// shape as anomaly/usecase.StartGC. onSummaries (may be nil) is called
// with each tick's aggregated summaries so main.go can also feed this
// instance's own local anomalies into its Correlator -- see
// PublishOnce's doc comment for why this is a callback here rather than
// a second Aggregate call in main.go.
//
// Each tick's PublishOnce call gets a context derived from stop rather
// than context.Background(), so an in-flight publish (each peer send has
// its own timeout, but several unreachable peers can still add up) is
// canceled promptly on shutdown instead of holding the process open --
// HTTPSender.Send already accepts and threads a cancelable context for
// exactly this.
func StartPublisher(p *Publisher, interval time.Duration, stop <-chan struct{}, onSummaries func([]domain.AnomalySummary), onError func([]error)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stop
		cancel()
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			summaries, errs := p.PublishOnce(ctx, now)
			if len(summaries) > 0 && onSummaries != nil {
				onSummaries(summaries)
			}
			if len(errs) > 0 && onError != nil {
				onError(errs)
			}
		}
	}
}
