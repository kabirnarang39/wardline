package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// TestRefreshToken_FieldsRoundTrip is a minimal shape test -- this
// package has no logic of its own yet (RefreshStore is an interface
// with no implementation here), so this just pins the struct's fields
// exist with the expected types, catching an accidental field rename in
// a future edit before it silently breaks every adapter that
// constructs one.
func TestRefreshToken_FieldsRoundTrip(t *testing.T) {
	now := time.Now()
	rt := domain.RefreshToken{
		Token:     "abc123",
		Identity:  "agent-abc123",
		Tenant:    "acme",
		ExpiresAt: now,
	}
	if rt.Token != "abc123" || rt.Identity != "agent-abc123" || rt.Tenant != "acme" || !rt.ExpiresAt.Equal(now) {
		t.Fatalf("unexpected field values: %+v", rt)
	}
}

func TestErrRefreshTokenInvalid_IsAStableSentinel(t *testing.T) {
	wrapped := errors.New("wrapped: " + domain.ErrRefreshTokenInvalid.Error())
	if errors.Is(wrapped, domain.ErrRefreshTokenInvalid) {
		t.Fatal("a manually-constructed error with matching text must NOT satisfy errors.Is -- callers must use %w wrapping, not string matching")
	}
	if !errors.Is(domain.ErrRefreshTokenInvalid, domain.ErrRefreshTokenInvalid) {
		t.Fatal("the sentinel must satisfy errors.Is against itself")
	}
}
