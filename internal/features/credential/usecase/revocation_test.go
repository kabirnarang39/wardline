package usecase_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

func TestRevocationService_RevokeDelegatesToRevoker(t *testing.T) {
	revoker := &fakeRevoker{}
	s := usecase.NewRevocationService(revoker)
	if err := s.Revoke("acme", "agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !revoker.IsRevoked("acme", "agent-abc123") {
		t.Error("expected RevocationService.Revoke to have called through to the Revoker")
	}
}

func TestRevocationService_RevokePropagatesRevokerError(t *testing.T) {
	wantErr := errors.New("backend unavailable")
	revoker := &fakeRevoker{err: wantErr}
	s := usecase.NewRevocationService(revoker)
	if err := s.Revoke("acme", "agent-abc123", time.Now().Add(time.Hour)); !errors.Is(err, wantErr) {
		t.Errorf("expected RevocationService.Revoke to propagate the Revoker's error, got %v", err)
	}
}

func TestRevocationService_RevokePassesTenantThrough(t *testing.T) {
	revoker := &fakeRevoker{}
	s := usecase.NewRevocationService(revoker)
	if err := s.Revoke("acme", "agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if revoker.lastTenant != "acme" || revoker.lastIdentity != "agent-abc123" {
		t.Errorf("Revoke called through with (%q, %q), want (\"acme\", \"agent-abc123\")", revoker.lastTenant, revoker.lastIdentity)
	}
}
