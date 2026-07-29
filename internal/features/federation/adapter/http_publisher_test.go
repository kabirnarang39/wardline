package adapter_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/federation/adapter"
	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

func TestHTTPSender_Send_PostsJSONBody(t *testing.T) {
	var receivedBody map[string]interface{}
	var receivedMethod, receivedPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := adapter.NewHTTPSender(&http.Client{Timeout: 5 * time.Second})

	batch := domain.SignedSummaryBatch{InstanceID: "local-instance", Signature: []byte{1, 2, 3}}
	err := sender.Send(context.Background(), srv.URL+"/federation/summaries", batch)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if receivedMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", receivedMethod)
	}
	if receivedPath != "/federation/summaries" {
		t.Errorf("expected path /federation/summaries, got %s", receivedPath)
	}
	if receivedBody["instance_id"] != "local-instance" {
		t.Errorf("expected instance_id local-instance, got %v", receivedBody["instance_id"])
	}
}

func TestHTTPSender_Send_NonOKStatus_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	sender := adapter.NewHTTPSender(&http.Client{Timeout: 5 * time.Second})

	err := sender.Send(context.Background(), srv.URL+"/federation/summaries", domain.SignedSummaryBatch{InstanceID: "local-instance"})
	if err == nil {
		t.Fatal("expected an error for a non-2xx response")
	}
}

func TestHTTPSender_Send_UnreachableEndpoint_ReturnsError(t *testing.T) {
	sender := adapter.NewHTTPSender(&http.Client{Timeout: 1 * time.Second})

	err := sender.Send(context.Background(), "http://127.0.0.1:1/federation/summaries", domain.SignedSummaryBatch{InstanceID: "local-instance"})
	if err == nil {
		t.Fatal("expected an error for an unreachable endpoint")
	}
}
