package adapter

import (
	"encoding/json"
	"net/http"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

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
}

func NewHandler(peers []domain.Peer, ingest func(instanceID string, s domain.AnomalySummary)) *Handler {
	byID := make(map[string]domain.Peer, len(peers))
	for _, p := range peers {
		byID[p.ID] = p
	}
	return &Handler{peers: byID, ingest: ingest}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	for _, s := range body.Summaries {
		h.ingest(body.InstanceID, s)
	}
	w.WriteHeader(http.StatusOK)
}
