package adapter

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

// maxSummaryBatchBytes caps how much of an inbound batch's request body
// we'll read before decoding. A peer's summary batch is a handful of
// small (fingerprint, kind, count, window) tuples, so 1 MiB is generous
// headroom, not a real limit in practice -- matching
// proxy/adapter.maxRequestBodyBytes and credential/adapter's
// maxTokenRequestBodyBytes, both applied the same way (MaxBytesReader
// before decode, on every POST handler in this codebase except this one
// until now).
const maxSummaryBatchBytes = 1 << 20 // 1 MiB

// maxBatchAge bounds how stale an inbound batch's aggregation window may
// be before it's rejected as a likely replay. A captured, valid
// SignedSummaryBatch has no nonce or timestamp of its own to prevent
// indefinite resending, so this is a coarse, defense-in-depth freshness
// check, not a real anti-replay protocol (nonce tracking is explicitly
// out of scope for this cycle) -- 10 minutes is generous relative to a
// typical publish_interval_seconds (60s default in wardline.yaml.example)
// so normal network/clock jitter never trips it, while still bounding how
// long a captured batch stays useful to keep a fingerprint artificially
// "fresh" in a peer's correlator.
const maxBatchAge = 10 * time.Minute

type inboundBatch struct {
	InstanceID string                  `json:"instance_id"`
	Summaries  []domain.AnomalySummary `json:"summaries"`
	Signature  []byte                  `json:"signature"`
}

// Handler serves POST /federation/summaries: verifies the sender's
// signature against that peer's registered public key, and on success
// calls ingest once per summary in the batch. An unrecognized
// instance_id or a signature that fails to verify is rejected with 401
// and never reaches ingest -- no partial trust.
type Handler struct {
	peers  map[string]domain.Peer
	ingest func(instanceID string, s domain.AnomalySummary)
	logger *slog.Logger
	now    func() time.Time
}

func NewHandler(peers []domain.Peer, ingest func(instanceID string, s domain.AnomalySummary), logger *slog.Logger) *Handler {
	byID := make(map[string]domain.Peer, len(peers))
	for _, p := range peers {
		byID[p.ID] = p
	}
	return &Handler{peers: byID, ingest: ingest, logger: logger, now: time.Now}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSummaryBatchBytes)

	var body inboundBatch
	// Decode into a struct without Signature first is unnecessary --
	// we need the exact bytes that were signed, so re-marshal the
	// instance_id+summaries pair the same way Publisher did, using the
	// decoded values (round-tripping through the same field order and
	// json tags as encoding/json.Marshal produces deterministically for
	// a fixed struct shape).
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return
	}

	peer, ok := h.peers[body.InstanceID]
	if !ok {
		h.logger.Warn("federation: rejected batch from unknown peer", "instance_id", body.InstanceID, "reason", "unknown peer")
		http.Error(w, "unknown peer", http.StatusUnauthorized)
		return
	}

	payload, err := json.Marshal(struct {
		InstanceID string                  `json:"instance_id"`
		Summaries  []domain.AnomalySummary `json:"summaries"`
	}{InstanceID: body.InstanceID, Summaries: body.Summaries})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !Verify(payload, body.Signature, peer.PublicKey) {
		h.logger.Warn("federation: rejected batch with invalid signature", "instance_id", body.InstanceID, "reason", "bad signature")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	if stale, windowEnd := h.isStale(body.Summaries); stale {
		h.logger.Warn("federation: rejected stale batch", "instance_id", body.InstanceID, "reason", "batch too old", "window_end", windowEnd)
		http.Error(w, "batch too old", http.StatusUnauthorized)
		return
	}

	for _, s := range body.Summaries {
		h.ingest(body.InstanceID, s)
	}
	w.WriteHeader(http.StatusOK)
}

// isStale reports whether the latest WindowEnd across summaries is older
// than maxBatchAge, plus that latest WindowEnd for logging. An empty
// summaries slice is never stale (nothing to reject).
func (h *Handler) isStale(summaries []domain.AnomalySummary) (bool, time.Time) {
	var maxWindowEnd time.Time
	for _, s := range summaries {
		if s.WindowEnd.After(maxWindowEnd) {
			maxWindowEnd = s.WindowEnd
		}
	}
	if maxWindowEnd.IsZero() {
		return false, maxWindowEnd
	}
	return h.now().Sub(maxWindowEnd) > maxBatchAge, maxWindowEnd
}
