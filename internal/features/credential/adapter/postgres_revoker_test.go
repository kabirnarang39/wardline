package adapter_test

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
)

// testDSN mirrors audit/adapter/postgres_writer_test.go's helper of the
// same name exactly -- same skip behavior, same env var, same "point at a
// disposable database only" warning.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres integration test")
	}
	return dsn
}

func dropRevokedIdentitiesTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS revoked_identities`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func TestPostgresRevoker_RevokeThenIsRevokedRoundTrips(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r.Close() }()

	r.Revoke("agent-abc123", time.Now().Add(time.Hour))

	if !r.IsRevoked("agent-abc123") {
		t.Error("expected agent-abc123 to be revoked")
	}
}

func TestPostgresRevoker_UnrevokedIdentityIsNotRevoked(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r.Close() }()

	if r.IsRevoked("never-revoked") {
		t.Error("expected an identity with no revocation entry to not be revoked")
	}
}

func TestPostgresRevoker_ExpiredRevocationSelfHeals(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r.Close() }()

	r.Revoke("agent-abc123", time.Now().Add(-time.Minute)) // already expired

	if r.IsRevoked("agent-abc123") {
		t.Error("expected an expired revocation to no longer count as revoked")
	}
}

func TestPostgresRevoker_TableCreationIsIdempotent(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r1, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("first NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r1.Close() }()

	r2, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("second NewPostgresRevoker (should be idempotent): %v", err)
	}
	defer func() { _ = r2.Close() }()
}

func TestNewPostgresRevoker_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresRevoker("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable")
	if err == nil {
		t.Fatal("expected an error constructing a revoker against an unreachable database")
	}
}

// TestPostgresRevoker_CrossInstanceRevocationPropagates is the actual HA
// scenario: two separate *PostgresRevoker instances (simulating two
// replicas) against the same DSN -- a revocation made through one is seen
// by the other, proven against a real shared database, not just the same
// in-process struct.
func TestPostgresRevoker_CrossInstanceRevocationPropagates(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	replicaA, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	defer func() { _ = replicaA.Close() }()

	replicaB, err := adapter.NewPostgresRevoker(dsn)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}
	defer func() { _ = replicaB.Close() }()

	replicaA.Revoke("agent-abc123", time.Now().Add(time.Hour))

	if !replicaB.IsRevoked("agent-abc123") {
		t.Error("expected a revocation made through replicaA to be visible through replicaB (same Postgres database)")
	}
}
