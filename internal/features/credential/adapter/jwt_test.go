package adapter_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

func TestJWTIssuerVerifier_RoundTrip(t *testing.T) {
	iv, err := adapter.NewJWTIssuerVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token, err := iv.Issue("agent-abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	claims, err := iv.Verify(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "agent-abc123" {
		t.Errorf("expected subject agent-abc123, got %q", claims.Subject)
	}
	if claims.ID == "" {
		t.Error("expected a non-empty jti")
	}
	if !claims.ExpiresAt.After(claims.IssuedAt) {
		t.Errorf("expected ExpiresAt after IssuedAt, got iat=%v exp=%v", claims.IssuedAt, claims.ExpiresAt)
	}
}

func TestJWTIssuerVerifier_TwoTokensHaveDifferentJTIs(t *testing.T) {
	iv, err := adapter.NewJWTIssuerVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t1, _ := iv.Issue("agent-abc123")
	t2, _ := iv.Issue("agent-abc123")
	c1, err := iv.Verify(t1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c2, err := iv.Verify(t2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c1.ID == c2.ID {
		t.Error("expected two issued tokens to have distinct jti values")
	}
}

func TestJWTIssuerVerifier_TamperedSignatureFails(t *testing.T) {
	iv, err := adapter.NewJWTIssuerVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token, _ := iv.Issue("agent-abc123")
	tampered := token[:len(token)-1] + "x"
	_, err = iv.Verify(tampered)
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestJWTIssuerVerifier_SignedByDifferentKeyFails(t *testing.T) {
	iv1, _ := adapter.NewJWTIssuerVerifier()
	iv2, _ := adapter.NewJWTIssuerVerifier()
	token, _ := iv1.Issue("agent-abc123")
	_, err := iv2.Verify(token)
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for a token signed by a different keypair, got %v", err)
	}
}

func TestJWTIssuerVerifier_ExpiredTokenFails(t *testing.T) {
	iv, err := adapter.NewJWTIssuerVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	adapter.SetClockForTest(iv, func() time.Time {
		return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	})
	token, _ := iv.Issue("agent-abc123")
	adapter.SetClockForTest(iv, func() time.Time {
		return time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC) // 1h later, past the 15m TTL
	})
	_, err = iv.Verify(token)
	if !errors.Is(err, domain.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestJWTIssuerVerifier_MalformedTokenFails(t *testing.T) {
	iv, err := adapter.NewJWTIssuerVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = iv.Verify("not-a-jwt-at-all")
	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got %v", err)
	}
}
