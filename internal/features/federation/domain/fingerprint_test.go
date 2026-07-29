package domain_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

func TestFingerprint_SameIdentitySameSecret_SameFingerprint(t *testing.T) {
	secret := []byte("shared-federation-secret")

	a := domain.Fingerprint("agent-abc123", secret)
	b := domain.Fingerprint("agent-abc123", secret)

	if a != b {
		t.Fatalf("expected same fingerprint for same identity+secret, got %q vs %q", a, b)
	}
}

func TestFingerprint_SameIdentityDifferentSecret_DifferentFingerprint(t *testing.T) {
	a := domain.Fingerprint("agent-abc123", []byte("secret-one"))
	b := domain.Fingerprint("agent-abc123", []byte("secret-two"))

	if a == b {
		t.Fatal("expected different fingerprints for the same identity under different secrets")
	}
}

func TestFingerprint_DifferentIdentitySameSecret_DifferentFingerprint(t *testing.T) {
	secret := []byte("shared-federation-secret")

	a := domain.Fingerprint("agent-abc123", secret)
	b := domain.Fingerprint("agent-xyz789", secret)

	if a == b {
		t.Fatal("expected different fingerprints for different identities under the same secret")
	}
}

func TestFingerprint_EmptySecret_StillDeterministic(t *testing.T) {
	a := domain.Fingerprint("agent-abc123", []byte{})
	b := domain.Fingerprint("agent-abc123", []byte{})

	if a != b {
		t.Fatal("expected fingerprint to be deterministic even with an empty secret")
	}
}
