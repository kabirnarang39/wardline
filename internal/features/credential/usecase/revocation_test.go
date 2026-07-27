package usecase_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

func TestRevocationService_RevokeDelegatesToRevoker(t *testing.T) {
	revoker := &fakeRevoker{}
	s := usecase.NewRevocationService(revoker)
	s.Revoke("agent-abc123", time.Now().Add(time.Hour))
	if !revoker.IsRevoked("agent-abc123") {
		t.Error("expected RevocationService.Revoke to have called through to the Revoker")
	}
}
