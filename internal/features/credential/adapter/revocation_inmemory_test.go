package adapter

import (
	"testing"
	"time"
)

func TestRevocationList_RevokedIdentityIsRevoked(t *testing.T) {
	r := NewRevocationList()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }

	_ = r.Revoke("acme", "agent-abc123", now.Add(time.Hour))
	if !r.IsRevoked("acme", "agent-abc123") {
		t.Error("expected agent-abc123 to be revoked")
	}
}

func TestRevocationList_UnrevokedIdentityIsNotRevoked(t *testing.T) {
	r := NewRevocationList()
	if r.IsRevoked("acme", "agent-never-revoked") {
		t.Error("expected an identity that was never revoked to not be revoked")
	}
}

func TestRevocationList_ExpiredRevocationSelfHeals(t *testing.T) {
	r := NewRevocationList()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	_ = r.Revoke("acme", "agent-abc123", now.Add(time.Minute))

	if !r.IsRevoked("acme", "agent-abc123") {
		t.Fatal("expected agent-abc123 to be revoked before its expiry")
	}

	r.now = func() time.Time { return now.Add(2 * time.Minute) } // past the 1-minute expiry
	if r.IsRevoked("acme", "agent-abc123") {
		t.Error("expected a revocation past its own expiry to be treated as not-revoked, without waiting for the sweep")
	}
}

func TestRevocationList_ConcurrentAccessIsSafe(t *testing.T) {
	r := NewRevocationList()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_ = r.Revoke("acme", "agent-a", time.Now().Add(time.Hour))
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		r.IsRevoked("acme", "agent-b")
	}
	<-done
}

func TestRevocationList_ScopedRevokeDoesNotAffectOtherTenant(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	r := NewRevocationList()
	r.now = func() time.Time { return now }

	if err := r.Revoke("acme", "alice", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if !r.IsRevoked("acme", "alice") {
		t.Error("expected acme's alice to be revoked")
	}
	if r.IsRevoked("widgets-inc", "alice") {
		t.Error("widgets-inc's alice must not be revoked by acme's revoke")
	}
}

func TestRevocationList_WildcardRevokeAffectsEveryTenant(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	r := NewRevocationList()
	r.now = func() time.Time { return now }

	// tenantName == "" -- target tenant unresolvable at revoke time.
	if err := r.Revoke("", "alice", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if !r.IsRevoked("acme", "alice") {
		t.Error("wildcard revoke must deny acme's alice")
	}
	if !r.IsRevoked("widgets-inc", "alice") {
		t.Error("wildcard revoke must deny widgets-inc's alice")
	}
}

func TestRevocationList_LegacyBareIdentityRowStillDeniesEveryTenant(t *testing.T) {
	// Simulates a row written before this task existed -- must read as a
	// wildcard, exactly like an explicit tenantName=="" revoke.
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	r := NewRevocationList()
	r.now = func() time.Time { return now }
	r.entries["alice"] = now.Add(time.Hour) // pre-migration shape: bare identity key

	if !r.IsRevoked("acme", "alice") {
		t.Error("legacy bare-identity row must deny acme's alice")
	}
	if !r.IsRevoked("widgets-inc", "alice") {
		t.Error("legacy bare-identity row must deny widgets-inc's alice")
	}
}

func TestRevocationList_ExpiredRevokeSelfHeals(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	r := NewRevocationList()
	r.now = func() time.Time { return now }

	if err := r.Revoke("acme", "alice", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if r.IsRevoked("acme", "alice") {
		t.Error("expired revoke must read as not-revoked")
	}
}
