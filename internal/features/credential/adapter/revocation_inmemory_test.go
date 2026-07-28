package adapter

import (
	"testing"
	"time"
)

func TestRevocationList_RevokedIdentityIsRevoked(t *testing.T) {
	r := NewRevocationList()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }

	_ = r.Revoke("agent-abc123", now.Add(time.Hour))
	if !r.IsRevoked("agent-abc123") {
		t.Error("expected agent-abc123 to be revoked")
	}
}

func TestRevocationList_UnrevokedIdentityIsNotRevoked(t *testing.T) {
	r := NewRevocationList()
	if r.IsRevoked("agent-never-revoked") {
		t.Error("expected an identity that was never revoked to not be revoked")
	}
}

func TestRevocationList_ExpiredRevocationSelfHeals(t *testing.T) {
	r := NewRevocationList()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	_ = r.Revoke("agent-abc123", now.Add(time.Minute))

	if !r.IsRevoked("agent-abc123") {
		t.Fatal("expected agent-abc123 to be revoked before its expiry")
	}

	r.now = func() time.Time { return now.Add(2 * time.Minute) } // past the 1-minute expiry
	if r.IsRevoked("agent-abc123") {
		t.Error("expected a revocation past its own expiry to be treated as not-revoked, without waiting for the sweep")
	}
}

func TestRevocationList_ConcurrentAccessIsSafe(t *testing.T) {
	r := NewRevocationList()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_ = r.Revoke("agent-a", time.Now().Add(time.Hour))
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		r.IsRevoked("agent-b")
	}
	<-done
}
