package usecase_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

// TestRevocationService_RevokeAlsoInvalidatesRefreshTokens is the
// load-bearing test from the design doc: /credentials/revoke must wipe
// outstanding refresh tokens, not just write a Revoker entry -- proves
// this end-to-end through RevocationService's own public surface (not
// by reaching into fakeRefreshStore's internals directly), so a future
// refactor of RevocationService.Revoke's internals can't silently drop
// this call while the test keeps passing.
func TestRevocationService_RevokeAlsoInvalidatesRefreshTokens(t *testing.T) {
	refreshStore := newFakeRefreshStore()
	_ = refreshStore.Issue("outstanding-refresh-tok", "agent-abc123", "acme", time.Now().Add(time.Hour))
	revoker := &fakeRevoker{}
	svc := usecase.NewRevocationService(revoker, refreshStore)

	if err := svc.Revoke("acme", "agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, _, err := refreshStore.Redeem("outstanding-refresh-tok"); err == nil {
		t.Error("expected Revoke to have invalidated the outstanding refresh token")
	}
	if refreshStore.revokedIdent != "agent-abc123" || refreshStore.revokedTenant != "acme" {
		t.Errorf("expected RevokeAllForIdentity called with (\"acme\", \"agent-abc123\"), got (%q, %q)", refreshStore.revokedTenant, refreshStore.revokedIdent)
	}
}

func TestRevocationService_RevokePropagatesRevokerError(t *testing.T) {
	refreshStore := newFakeRefreshStore()
	revoker := &erroringRevoker{}
	svc := usecase.NewRevocationService(revoker, refreshStore)

	if err := svc.Revoke("acme", "agent-abc123", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected the Revoker's write error to propagate")
	}
}

type erroringRevoker struct{}

func (e *erroringRevoker) Revoke(tenantName, identity string, expiresAt time.Time) error {
	return errWriteFailed
}
func (e *erroringRevoker) IsRevoked(tenantName, identity string) bool { return false }

var errWriteFailed = errors.New("write failed")
