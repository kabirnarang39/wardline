package adapter_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
	"github.com/kabirnarang39/wardline/internal/features/credential/usecase"
)

const refreshTestSchema = "wardline_test_credential_refresh"

func refreshTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open to create test schema: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + refreshTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + refreshTestSchema
}

func dropRefreshTokensTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS refresh_tokens`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func TestPostgresRefreshStore_IssueThenRedeemRoundTrips(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	identity, tenantName, err := s.Redeem("tok-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if identity != "agent-abc123" || tenantName != "acme" {
		t.Errorf("got (%q, %q), want (\"agent-abc123\", \"acme\")", identity, tenantName)
	}
}

func TestPostgresRefreshStore_RedeemIsSingleUse(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := s.Redeem("tok-1"); err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid redeeming an already-used token, got %v", err)
	}
}

func TestPostgresRefreshStore_RedeemUnknownTokenFails(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if _, _, err := s.Redeem("never-issued"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for a never-issued token, got %v", err)
	}
}

func TestPostgresRefreshStore_RedeemExpiredTokenFails(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected ErrRefreshTokenInvalid for an expired token, got %v", err)
	}
}

func TestPostgresRefreshStore_RevokeAllForIdentityInvalidatesItsTokens(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-1: %v", err)
	}
	if err := s.Issue("tok-2", "agent-xyz789", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue tok-2: %v", err)
	}

	if err := s.RevokeAllForIdentity("acme", "agent-abc123"); err != nil {
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, err := s.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected tok-1 to be invalidated, got err=%v", err)
	}
	if _, _, err := s.Redeem("tok-2"); err != nil {
		t.Errorf("expected a different identity's token to survive, got err=%v", err)
	}
}

func TestPostgresRefreshStore_WildcardRevokeAffectsEveryTenant(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Issue("tok-acme", "bob", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Issue("tok-widgets", "bob", "widgets-inc", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := s.RevokeAllForIdentity("", "bob"); err != nil {
		t.Fatalf("RevokeAllForIdentity: %v", err)
	}

	if _, _, err := s.Redeem("tok-acme"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected wildcard revoke to invalidate acme's bob token, got err=%v", err)
	}
	if _, _, err := s.Redeem("tok-widgets"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Errorf("expected wildcard revoke to invalidate widgets-inc's bob token, got err=%v", err)
	}
}

func TestPostgresRefreshStore_TableCreationIsIdempotent(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	s1, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("first NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = s1.Close() }()

	s2, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("second NewPostgresRefreshStore (should be idempotent): %v", err)
	}
	defer func() { _ = s2.Close() }()
}

func TestNewPostgresRefreshStore_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresRefreshStore("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable")
	if err == nil {
		t.Fatal("expected an error constructing a store against an unreachable database")
	}
}

// TestPostgresRefreshStore_CrossInstanceRedeemPropagates is the actual HA
// scenario: two separate *PostgresRefreshStore instances (simulating two
// replicas) against the same DSN -- a token issued through one is
// redeemable through the other, and the redeem's single-use deletion is
// visible cross-instance too.
func TestPostgresRefreshStore_CrossInstanceRedeemPropagates(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	replicaA, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	defer func() { _ = replicaA.Close() }()

	replicaB, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}
	defer func() { _ = replicaB.Close() }()

	if err := replicaA.Issue("tok-1", "agent-abc123", "acme", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := replicaB.Redeem("tok-1"); err != nil {
		t.Fatalf("expected replicaB to redeem a token issued through replicaA: %v", err)
	}
	if _, _, err := replicaA.Redeem("tok-1"); !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Error("expected replicaA to see the token as already-redeemed (single-use is cross-instance)")
	}
}

// TestRefreshTokensSurviveNothingAfterWildcardRevoke_EndToEnd is the
// composed security property the Postgres-adapter-level SQL bug broke,
// proven through the real usecase services against a real database
// rather than through the store's own methods: bootstrap an identity,
// revoke it the way bootstrap_source: oidc always does (tenantName ==
// "", because identityTenantLookup is hardcoded to fail there), and the
// refresh token it was handed at bootstrap must be dead.
//
// This lives here rather than in usecase/ because usecase's own tests
// deliberately don't import adapter (Clean Architecture's dependency
// direction), and a fake refresh store could never have caught this --
// the bug was in the DELETE's WHERE clause, nowhere else. Before the
// fix, the revoke silently matched no rows and this Refresh returned a
// brand-new access+refresh pair for an identity that had just been
// revoked, renewable forever once the access-token revocation window
// (access_token_ttl_seconds, default 15m) elapsed.
func TestRefreshTokensSurviveNothingAfterWildcardRevoke_EndToEnd(t *testing.T) {
	dsn := refreshTestDSN(t)
	dropRefreshTokensTable(t, dsn)

	store, err := adapter.NewPostgresRefreshStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRefreshStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	credsPath := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(credsPath, []byte("identities:\n  - name: agent-abc123\n    secret: s3cret\n    tenant: acme\n"), 0o600); err != nil {
		t.Fatalf("write credentials file: %v", err)
	}
	bootstrapper, err := adapter.LoadBootstrapper(credsPath)
	if err != nil {
		t.Fatalf("LoadBootstrapper: %v", err)
	}
	issuer, err := adapter.NewJWTIssuerVerifier("", 15*time.Minute)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifier: %v", err)
	}
	revoker := adapter.NewRevocationList()

	issuance := usecase.NewIssuanceService(bootstrapper, issuer, store, time.Hour)
	revocation := usecase.NewRevocationService(revoker, store)
	refresh := usecase.NewRefreshService(store, revoker, issuer, time.Hour, time.Now)

	_, refreshToken, err := issuance.Bootstrap("s3cret")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// The wildcard revoke: tenantName == "", exactly what serve does for
	// every revoke under bootstrap_source: oidc. The revocation horizon
	// is deliberately tiny here: in production it is
	// access_token_ttl_seconds (default 15m), and the Revoker entry is
	// only meant to cover the window in which already-issued access
	// tokens are still valid. Sleeping past it is what isolates the
	// refresh store as the thing under test -- while the Revoker entry
	// is still live, RefreshService's own IsRevoked check masks a
	// surviving refresh token, which is exactly why the original bug
	// stayed invisible until the horizon elapsed.
	if err := revocation.Revoke("", "agent-abc123", time.Now().Add(150*time.Millisecond)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if revoker.IsRevoked("acme", "agent-abc123") {
		t.Fatal("test setup: expected the revocation horizon to have elapsed by now")
	}

	accessToken, rotatedRefreshToken, err := refresh.Refresh(refreshToken)
	if !errors.Is(err, domain.ErrRefreshTokenInvalid) {
		t.Fatalf("a revoked identity's bootstrap refresh token must be dead once the revocation horizon elapses, got (%q, %q, %v) -- a fresh access token AND a fresh refresh token for a revoked identity, renewable forever", accessToken, rotatedRefreshToken, err)
	}
}
