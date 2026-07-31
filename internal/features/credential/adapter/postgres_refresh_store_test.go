package adapter_test

import (
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
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
