package usecase_test

import (
	"errors"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

type fakeBootstrapper struct {
	identity string
	err      error
}

func (f fakeBootstrapper) Authenticate(secret string) (string, error) {
	return f.identity, f.err
}

type fakeIssuer struct {
	token string
	err   error
}

func (f fakeIssuer) Issue(identity string) (string, error) {
	return f.token, f.err
}

func TestIssuanceService_ValidSecretReturnsToken(t *testing.T) {
	s := usecase.NewIssuanceService(fakeBootstrapper{identity: "agent-abc123"}, fakeIssuer{token: "signed-jwt"})
	token, err := s.Bootstrap("any-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "signed-jwt" {
		t.Errorf("expected signed-jwt, got %q", token)
	}
}

func TestIssuanceService_BootstrapperFailurePropagates(t *testing.T) {
	s := usecase.NewIssuanceService(fakeBootstrapper{err: domain.ErrInvalidCredentials}, fakeIssuer{token: "should-not-be-issued"})
	_, err := s.Bootstrap("wrong-secret")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}
