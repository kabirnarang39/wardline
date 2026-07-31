package adapter_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

func TestInMemoryRefreshStore_IssueThenRedeemRoundTrips(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	identity, tenantName, err := s.Redeem("tok-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if identity != "agent-abc123" || tenantName != "acme" {
		t.Errorf("got (%q, %q), want (\"agent-abc123\", \"acme\")", identity, tenantName)
	}
}

func TestInMemoryRefreshStore_RedeemIsSingleUse(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := s.Redeem("tok-1"); err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid redeeming an already-used token, got %v", err)
	}
}

func TestInMemoryRefreshStore_RedeemUnknownTokenFails(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if _, _, err := s.Redeem("never-issued"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for a never-issued token, got %v", err)
	}
}

func TestInMemoryRefreshStore_RedeemExpiredTokenFails(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(-time.Minute)); err != nil { // already expired
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for an expired token, got %v", err)
	}
}

func TestInMemoryRefreshStore_RevokeAllForIdentityInvalidatesItsTokens(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-1: %v", err)
	}
	if err := s.Issue("tok-2", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-2: %v", err)
	}
	// A different identity's token must survive.
	if err := s.Issue("tok-3", "agent-xyz789", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-3: %v", err)
	}

	if err := s.RevokeAllForIdentity("acme", "agent-abc123"); err != nil {
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected tok-1 to be invalidated by RevokeAllForIdentity, got err=%v", err)
	}
	if _, _, err := s.Redeem("tok-2"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected tok-2 to be invalidated by RevokeAllForIdentity, got err=%v", err)
	}
	if _, _, err := s.Redeem("tok-3"); err != nil {
		t.Errorf("expected a DIFFERENT identity's token to survive, got err=%v", err)
	}
}

func TestInMemoryRefreshStore_RevokeAllForIdentityIsScopedToTenant(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-acme", "alice", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Issue("tok-widgets", "alice", "widgets-inc", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := s.RevokeAllForIdentity("acme", "alice"); err != nil {
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, err := s.Redeem("tok-acme"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected acme's alice token to be invalidated, got err=%v", err)
	}
	if _, _, err := s.Redeem("tok-widgets"); err != nil {
		t.Errorf("expected widgets-inc's alice token to survive a tenant-scoped revoke of acme's alice, got err=%v", err)
	}
}

func TestInMemoryRefreshStore_WildcardRevokeAllForIdentityAffectsEveryTenant(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-acme", "bob", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Issue("tok-widgets", "bob", "widgets-inc", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := s.RevokeAllForIdentity("", "bob"); err != nil { // "" == wildcard, matches domain.Revoker's convention
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, err := s.Redeem("tok-acme"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected a wildcard revoke to invalidate acme's bob token, got err=%v", err)
	}
	if _, _, err := s.Redeem("tok-widgets"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected a wildcard revoke to invalidate widgets-inc's bob token, got err=%v", err)
	}
}
