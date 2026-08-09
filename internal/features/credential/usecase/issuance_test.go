package usecase_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

type fakeBootstrapper struct {
	identity, tenant string
	err              error
}

func (f *fakeBootstrapper) Authenticate(secret string) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	return f.identity, f.tenant, nil
}

func TestIssuanceService_BootstrapReturnsAccessAndRefreshTokens(t *testing.T) {
	bootstrapper := &fakeBootstrapper{identity: "agent-abc123", tenant: "acme"}
	issuer := &fakeIssuer{}
	store := newFakeRefreshStore()
	svc := usecase.NewIssuanceService(bootstrapper, issuer, store, time.Hour)

	accessToken, refreshToken, err := svc.Bootstrap("any-secret")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if accessToken != "access-token-for-agent-abc123" {
		t.Errorf("unexpected access token: %q", accessToken)
	}
	if refreshToken == "" {
		t.Error("expected a non-empty refresh token from bootstrap")
	}
	// The refresh token issued at bootstrap must actually be redeemable
	// afterward -- proves IssuanceService and RefreshService share the
	// same RefreshStore correctly, not two independent stores.
	identity, tenantName, _, err := store.Redeem(refreshToken)
	if err != nil {
		t.Fatalf("expected the bootstrap-issued refresh token to be redeemable: %v", err)
	}
	if identity != "agent-abc123" || tenantName != "acme" {
		t.Errorf("got (%q, %q), want (\"agent-abc123\", \"acme\")", identity, tenantName)
	}
}

func TestIssuanceService_BootstrapPropagatesBootstrapperError(t *testing.T) {
	bootstrapper := &fakeBootstrapper{err: domain.ErrInvalidCredentials}
	svc := usecase.NewIssuanceService(bootstrapper, &fakeIssuer{}, newFakeRefreshStore(), time.Hour)

	_, _, err := svc.Bootstrap("wrong-secret")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials to propagate unchanged, got %v", err)
	}
}
