package adapter_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/features/federation/adapter"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

func generateHandlerTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, &priv.PublicKey
}

func signedBody(t *testing.T, priv *rsa.PrivateKey, instanceID string, summaries []domain.AnomalySummary) []byte {
	t.Helper()
	payload, err := json.Marshal(struct {
		InstanceID string                  `json:"instance_id"`
		Summaries  []domain.AnomalySummary `json:"summaries"`
	}{InstanceID: instanceID, Summaries: summaries})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig, err := adapter.Sign(payload, priv)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	full, err := json.Marshal(struct {
		InstanceID string                  `json:"instance_id"`
		Summaries  []domain.AnomalySummary `json:"summaries"`
		Signature  []byte                  `json:"signature"`
	}{InstanceID: instanceID, Summaries: summaries, Signature: sig})
	if err != nil {
		t.Fatalf("marshal full body: %v", err)
	}
	return full
}

func TestHandler_ValidSignature_ReachesIngest(t *testing.T) {
	priv, pub := generateHandlerTestKeyPair(t)
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com", PublicKey: pub}}

	var mu sync.Mutex
	var ingested []domain.AnomalySummary
	ingest := func(instanceID string, s domain.AnomalySummary) {
		mu.Lock()
		defer mu.Unlock()
		ingested = append(ingested, s)
	}

	h := adapter.NewHandler(peers, ingest)

	summaries := []domain.AnomalySummary{{Fingerprint: "fp1", Kind: anomalydomain.KindRateSpike, Count: 3}}
	body := signedBody(t, priv, "eu-cluster", summaries)

	req := httptest.NewRequest(http.MethodPost, "/federation/summaries", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ingested) != 1 || ingested[0].Fingerprint != "fp1" {
		t.Fatalf("expected 1 ingested summary with fingerprint fp1, got %+v", ingested)
	}
}

func TestHandler_UnknownPeerID_Returns401AndDoesNotIngest(t *testing.T) {
	_, pub := generateHandlerTestKeyPair(t)
	otherPriv, _ := generateHandlerTestKeyPair(t)
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com", PublicKey: pub}}

	var mu sync.Mutex
	ingestedCount := 0
	ingest := func(instanceID string, s domain.AnomalySummary) {
		mu.Lock()
		defer mu.Unlock()
		ingestedCount++
	}

	h := adapter.NewHandler(peers, ingest)

	body := signedBody(t, otherPriv, "unknown-cluster", []domain.AnomalySummary{{Fingerprint: "fp1"}})

	req := httptest.NewRequest(http.MethodPost, "/federation/summaries", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown peer, got %d", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if ingestedCount != 0 {
		t.Fatal("expected no ingest call for an unknown peer")
	}
}

func TestHandler_BadSignature_Returns401AndDoesNotIngest(t *testing.T) {
	_, pub := generateHandlerTestKeyPair(t)
	wrongPriv, _ := generateHandlerTestKeyPair(t) // signed with the WRONG key for "eu-cluster"
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com", PublicKey: pub}}

	var mu sync.Mutex
	ingestedCount := 0
	ingest := func(instanceID string, s domain.AnomalySummary) {
		mu.Lock()
		defer mu.Unlock()
		ingestedCount++
	}

	h := adapter.NewHandler(peers, ingest)

	body := signedBody(t, wrongPriv, "eu-cluster", []domain.AnomalySummary{{Fingerprint: "fp1"}})

	req := httptest.NewRequest(http.MethodPost, "/federation/summaries", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bad signature, got %d", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if ingestedCount != 0 {
		t.Fatal("expected no ingest call for a bad signature")
	}
}

func TestHandler_MalformedBody_Returns400(t *testing.T) {
	_, pub := generateHandlerTestKeyPair(t)
	peers := []domain.Peer{{ID: "eu-cluster", Endpoint: "https://eu.example.com", PublicKey: pub}}

	h := adapter.NewHandler(peers, func(string, domain.AnomalySummary) {})

	req := httptest.NewRequest(http.MethodPost, "/federation/summaries", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got %d", rec.Code)
	}
}
