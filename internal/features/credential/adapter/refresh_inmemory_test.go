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
	if err := s.Issue("tok-1", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	identity, tenantName, family, err := s.Redeem("tok-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if identity != "agent-abc123" || tenantName != "acme" || family != "fam-1" {
		t.Errorf("got (%q, %q, %q), want (\"agent-abc123\", \"acme\", \"fam-1\")", identity, tenantName, family)
	}
}

func TestInMemoryRefreshStore_ReplayingAConsumedTokenIsReuse(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, _, err := s.Redeem("tok-1"); err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	// A consumed token replayed is the theft signal, not an ordinary invalid.
	if _, _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenReused) {
		t.Errorf("expected ErrRefreshTokenReused replaying a consumed token, got %v", err)
	}
}

// TestInMemoryRefreshStore_ReuseRevokesTheWholeFamily proves the theft
// response: replaying a consumed token wipes every other token in its
// family, including the legitimate current rotation.
func TestInMemoryRefreshStore_ReuseRevokesTheWholeFamily(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	// Two tokens in the same family (a bootstrap and its rotation), plus one
	// in a different family that must survive.
	if err := s.Issue("old-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue old-tok: %v", err)
	}
	if err := s.Issue("current-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue current-tok: %v", err)
	}
	if err := s.Issue("other-family-tok", "agent-abc123", "acme", "fam-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue other-family-tok: %v", err)
	}

	// Consume old-tok, then replay it -> reuse -> family fam-1 revoked.
	if _, _, _, err := s.Redeem("old-tok"); err != nil {
		t.Fatalf("consume old-tok: %v", err)
	}
	if _, _, _, err := s.Redeem("old-tok"); !errors.Is(err, domain.ErrRefreshTokenReused) {
		t.Fatalf("expected reuse on replay, got %v", err)
	}

	// current-tok (same family) is dead; other-family-tok survives.
	if _, _, _, err := s.Redeem("current-tok"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected the family's current token to be revoked, got %v", err)
	}
	if _, _, _, err := s.Redeem("other-family-tok"); err != nil {
		t.Errorf("expected a different family's token to survive, got %v", err)
	}
}

func TestInMemoryRefreshStore_RedeemUnknownTokenFails(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if _, _, _, err := s.Redeem("never-issued"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for a never-issued token, got %v", err)
	}
}

func TestInMemoryRefreshStore_RedeemExpiredTokenFails(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", "fam-1", time.Now().Add(-time.Minute)); err != nil { // already expired
		t.Fatalf("Issue: %v", err)
	}
	if _, _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for an expired token, got %v", err)
	}
}

func TestInMemoryRefreshStore_RevokeAllForIdentityInvalidatesItsTokens(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-1", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-1: %v", err)
	}
	if err := s.Issue("tok-2", "agent-abc123", "acme", "fam-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-2: %v", err)
	}
	// A different identity's token must survive.
	if err := s.Issue("tok-3", "agent-xyz789", "acme", "fam-3", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-3: %v", err)
	}

	if err := s.RevokeAllForIdentity("acme", "agent-abc123"); err != nil {
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected tok-1 to be invalidated by RevokeAllForIdentity, got err=%v", err)
	}
	if _, _, _, err := s.Redeem("tok-2"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected tok-2 to be invalidated by RevokeAllForIdentity, got err=%v", err)
	}
	if _, _, _, err := s.Redeem("tok-3"); err != nil {
		t.Errorf("expected a DIFFERENT identity's token to survive, got err=%v", err)
	}
}

func TestInMemoryRefreshStore_RevokeAllForIdentityIsScopedToTenant(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-acme", "alice", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Issue("tok-widgets", "alice", "widgets-inc", "fam-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := s.RevokeAllForIdentity("acme", "alice"); err != nil {
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, _, err := s.Redeem("tok-acme"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected acme's alice token to be invalidated, got err=%v", err)
	}
	if _, _, _, err := s.Redeem("tok-widgets"); err != nil {
		t.Errorf("expected widgets-inc's alice token to survive a tenant-scoped revoke of acme's alice, got err=%v", err)
	}
}

func TestInMemoryRefreshStore_WildcardRevokeAllForIdentityAffectsEveryTenant(t *testing.T) {
	s := adapter.NewInMemoryRefreshStore()
	if err := s.Issue("tok-acme", "bob", "acme", "fam-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Issue("tok-widgets", "bob", "widgets-inc", "fam-2", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := s.RevokeAllForIdentity("", "bob"); err != nil { // "" == wildcard, matches domain.Revoker's convention
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, _, err := s.Redeem("tok-acme"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected a wildcard revoke to invalidate acme's bob token, got err=%v", err)
	}
	if _, _, _, err := s.Redeem("tok-widgets"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected a wildcard revoke to invalidate widgets-inc's bob token, got err=%v", err)
	}
}
