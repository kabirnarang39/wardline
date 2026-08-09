package usecase_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

// fakeRefreshStore is a minimal in-test domain.RefreshStore -- separate
// from internal/features/credential/adapter's real InMemoryRefreshStore
// so this usecase package's tests don't depend on the adapter package
// (matching Clean Architecture's dependency direction: usecase must not
// import adapter).
type fakeRefreshEntry struct {
	identity string
	tenant   string
	family   string
	consumed bool
}

type fakeRefreshStore struct {
	issued        map[string]fakeRefreshEntry
	redeemErr     error
	revokedIdent  string
	revokedTenant string
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{issued: make(map[string]fakeRefreshEntry)}
}

func (f *fakeRefreshStore) Issue(token, identity, tenantName, family string, expiresAt time.Time) error {
	f.issued[token] = fakeRefreshEntry{identity: identity, tenant: tenantName, family: family}
	return nil
}

// Redeem mirrors the real stores' reuse-detecting state machine so
// RefreshService tests exercise real behavior: active token -> consumed;
// replay of a consumed token -> whole family revoked + ErrRefreshTokenReused.
func (f *fakeRefreshStore) Redeem(token string) (string, string, string, error) {
	if f.redeemErr != nil {
		return "", "", "", f.redeemErr
	}
	entry, ok := f.issued[token]
	if !ok {
		return "", "", "", domain.ErrRefreshTokenInvalid
	}
	if entry.consumed {
		for tok, e := range f.issued {
			if e.family == entry.family {
				delete(f.issued, tok)
			}
		}
		return "", "", "", domain.ErrRefreshTokenReused
	}
	entry.consumed = true
	f.issued[token] = entry
	return entry.identity, entry.tenant, entry.family, nil
}

func (f *fakeRefreshStore) RevokeAllForIdentity(tenantName, identity string) error {
	f.revokedTenant, f.revokedIdent = tenantName, identity
	for tok, entry := range f.issued {
		if entry.identity == identity && (tenantName == "" || entry.tenant == tenantName) {
			delete(f.issued, tok)
		}
	}
	return nil
}

// fakeRefreshRevoker is distinct from verification_test.go's fakeRevoker
// (which only keys revocation by identity, not tenant) -- RefreshService's
// ordering test below needs a revoker that matches on the exact
// (tenant, identity) pair, so it gets its own small fake rather than
// reusing or widening the existing one.
type fakeRefreshRevoker struct {
	revokedIdentity string
	revokedTenant   string
}

func (f *fakeRefreshRevoker) Revoke(tenantName, identity string, expiresAt time.Time) error {
	return nil
}

func (f *fakeRefreshRevoker) IsRevoked(tenantName, identity string) bool {
	return identity == f.revokedIdentity && tenantName == f.revokedTenant
}

type fakeIssuer struct {
	issueCount int
}

func (f *fakeIssuer) Issue(identity, tenant string) (string, error) {
	f.issueCount++
	return "access-token-for-" + identity, nil
}

func TestRefreshService_ValidTokenIssuesNewAccessAndRefreshTokens(t *testing.T) {
	store := newFakeRefreshStore()
	_ = store.Issue("old-refresh-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour))
	revoker := &fakeRefreshRevoker{}
	issuer := &fakeIssuer{}
	svc := usecase.NewRefreshService(store, revoker, issuer, time.Hour, time.Now)

	accessToken, newRefreshToken, err := svc.Refresh("old-refresh-tok")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if accessToken != "access-token-for-agent-abc123" {
		t.Errorf("unexpected access token: %q", accessToken)
	}
	if newRefreshToken == "" || newRefreshToken == "old-refresh-tok" {
		t.Errorf("expected a NEW, non-empty refresh token, got %q", newRefreshToken)
	}
}

func TestRefreshService_ReplayingARotatedTokenIsDetectedAsReuse(t *testing.T) {
	store := newFakeRefreshStore()
	_ = store.Issue("old-refresh-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour))
	svc := usecase.NewRefreshService(store, &fakeRefreshRevoker{}, &fakeIssuer{}, time.Hour, time.Now)

	if _, _, err := svc.Refresh("old-refresh-tok"); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	// Replaying the now-consumed token is the theft signal: the store
	// reports reuse (and has revoked the family), which the service
	// propagates for the handler to log.
	if _, _, err := svc.Refresh("old-refresh-tok"); !errors.Is(err, domain.ErrRefreshTokenReused) {
		t.Errorf("expected replay of a rotated-away token to be detected as reuse, got %v", err)
	}
}

// TestRefreshService_ReuseRevokesTheWholeFamily proves the theft response:
// after a legitimate rotation, replaying the old (consumed) token revokes
// the entire lineage, so even the current, legitimately-issued token in
// that family stops working.
func TestRefreshService_ReuseRevokesTheWholeFamily(t *testing.T) {
	store := newFakeRefreshStore()
	_ = store.Issue("bootstrap-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour))
	svc := usecase.NewRefreshService(store, &fakeRefreshRevoker{}, &fakeIssuer{}, time.Hour, time.Now)

	// Legitimate rotation: bootstrap-tok -> current-tok (same family).
	_, currentTok, err := svc.Refresh("bootstrap-tok")
	if err != nil {
		t.Fatalf("legitimate rotation: %v", err)
	}

	// Attacker replays the stolen, already-consumed bootstrap-tok.
	if _, _, err := svc.Refresh("bootstrap-tok"); !errors.Is(err, domain.ErrRefreshTokenReused) {
		t.Fatalf("expected reuse detection on replay, got %v", err)
	}

	// The legitimate current token is now dead too -- the whole family was revoked.
	if _, _, err := svc.Refresh(currentTok); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected the current token to be invalidated by the family revocation, got %v", err)
	}
}

func TestRefreshService_UnknownTokenFails(t *testing.T) {
	store := newFakeRefreshStore()
	svc := usecase.NewRefreshService(store, &fakeRefreshRevoker{}, &fakeIssuer{}, time.Hour, time.Now)

	if _, _, err := svc.Refresh("never-issued"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid, got %v", err)
	}
}

// TestRefreshService_RevokedIdentityFailsEvenWithAStillValidRefreshToken
// is the load-bearing ordering test from the design spec: a refresh
// token that hasn't expired and hasn't been used yet must STILL be
// rejected if the identity it belongs to is currently revoked -- this is
// what keeps HandleRevoke's revocation-expiry math sound once refresh
// tokens exist (see design doc "Interaction with revocation").
func TestRefreshService_RevokedIdentityFailsEvenWithAStillValidRefreshToken(t *testing.T) {
	store := newFakeRefreshStore()
	_ = store.Issue("still-valid-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(time.Hour))
	revoker := &fakeRefreshRevoker{revokedIdentity: "agent-abc123", revokedTenant: "acme"}
	issuer := &fakeIssuer{}
	svc := usecase.NewRefreshService(store, revoker, issuer, time.Hour, time.Now)

	if _, _, err := svc.Refresh("still-valid-tok"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected a revoked identity's still-valid refresh token to be rejected, got %v", err)
	}
	if issuer.issueCount != 0 {
		t.Error("expected NO new access token to be issued for a revoked identity")
	}
}

func TestRefreshService_ExpiredTokenFails(t *testing.T) {
	store := newFakeRefreshStore()
	_ = store.Issue("expired-tok", "agent-abc123", "acme", "fam-1", time.Now().Add(-time.Minute))
	svc := usecase.NewRefreshService(store, &fakeRefreshRevoker{}, &fakeIssuer{}, time.Hour, time.Now)

	// fakeRefreshStore's Redeem above doesn't itself check expiry (the
	// real adapters do -- see Tasks 2-3); simulate the adapter-level
	// rejection by setting redeemErr directly instead, since this test's
	// job is to prove RefreshService correctly PROPAGATES that error, not
	// to re-test expiry logic the real adapters already cover.
	store.redeemErr = domain.ErrRefreshTokenInvalid
	if _, _, err := svc.Refresh("expired-tok"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid to propagate, got %v", err)
	}
}
