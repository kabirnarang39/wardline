package usecase_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

type fakeVerifier struct {
	claims domain.Claims
	err    error
}

func (f fakeVerifier) Verify(token string) (domain.Claims, error) {
	return f.claims, f.err
}

type fakeRevoker struct {
	revoked map[string]bool
	err     error // when set, Revoke returns this instead of recording
}

func (f *fakeRevoker) Revoke(identity string, expiresAt time.Time) error {
	if f.err != nil {
		return f.err
	}
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[identity] = true
	return nil
}

func (f *fakeRevoker) IsRevoked(identity string) bool {
	return f.revoked[identity]
}

func TestVerificationService_ValidUnrevokedTokenReturnsIdentity(t *testing.T) {
	s := usecase.NewVerificationService(fakeVerifier{claims: domain.Claims{Subject: "agent-abc123"}}, &fakeRevoker{})
	identity, err := s.Authenticate("some-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity != "agent-abc123" {
		t.Errorf("expected agent-abc123, got %q", identity)
	}
}

func TestVerificationService_VerifierFailurePropagates(t *testing.T) {
	s := usecase.NewVerificationService(fakeVerifier{err: domain.ErrTokenExpired}, &fakeRevoker{})
	_, err := s.Authenticate("expired-token")
	if !errors.Is(err, domain.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerificationService_RevokedIdentityIsRejected(t *testing.T) {
	revoker := &fakeRevoker{revoked: map[string]bool{"agent-abc123": true}}
	s := usecase.NewVerificationService(fakeVerifier{claims: domain.Claims{Subject: "agent-abc123"}}, revoker)
	_, err := s.Authenticate("valid-but-revoked-token")
	if !errors.Is(err, usecase.ErrRevoked) {
		t.Errorf("expected ErrRevoked, got %v", err)
	}
}
