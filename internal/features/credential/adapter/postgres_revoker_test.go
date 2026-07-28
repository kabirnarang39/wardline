package adapter_test

import (
	"bytes"
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
)

// testSchema isolates this package's Postgres tests from every other
// package's (internal/features/audit/adapter and cmd/wardline both run
// their own real-Postgres tests against the same
// WARDLINE_TEST_POSTGRES_DSN-pointed database, and go test ./...
// schedules different packages' test binaries concurrently) -- without
// this, a DROP TABLE from one package can race a live query/insert from
// another against tables of the same name in the shared "public" schema.
const testSchema = "wardline_test_credential"

// testDSN mirrors audit/adapter/postgres_writer_test.go's helper of the
// same name -- same skip behavior, same env var, same "point at a
// disposable database only" warning, plus search_path pinned to
// testSchema so every table this package's tests create or drop stays
// confined to it.
func testDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + testSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + testSchema
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

	r, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r.Close() }()

	if err := r.Revoke("agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if !r.IsRevoked("agent-abc123") {
		t.Error("expected agent-abc123 to be revoked")
	}
}

func TestPostgresRevoker_UnrevokedIdentityIsNotRevoked(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r, err := adapter.NewPostgresRevoker(dsn, nil)
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

	r, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r.Close() }()

	if err := r.Revoke("agent-abc123", time.Now().Add(-time.Minute)); err != nil { // already expired
		t.Fatalf("Revoke: %v", err)
	}

	if r.IsRevoked("agent-abc123") {
		t.Error("expected an expired revocation to no longer count as revoked")
	}
}

func TestPostgresRevoker_TableCreationIsIdempotent(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r1, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("first NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r1.Close() }()

	r2, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("second NewPostgresRevoker (should be idempotent): %v", err)
	}
	defer func() { _ = r2.Close() }()
}

func TestNewPostgresRevoker_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresRevoker("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable", nil)
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

	replicaA, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	defer func() { _ = replicaA.Close() }()

	replicaB, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}
	defer func() { _ = replicaB.Close() }()

	if err := replicaA.Revoke("agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if !replicaB.IsRevoked("agent-abc123") {
		t.Error("expected a revocation made through replicaA to be visible through replicaB (same Postgres database)")
	}
}

func TestPostgresRevoker_RevokeAgainstClosedPoolReturnsError(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	r, err := adapter.NewPostgresRevoker(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := r.Revoke("agent-abc123", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected Revoke against a closed connection pool to return an error")
	}
}

func TestPostgresRevoker_IsRevoked_QueryErrorIsLoggedAndFailsOpen(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	r, err := adapter.NewPostgresRevoker(dsn, logger)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Query against a closed pool -- a real error, not sql.ErrNoRows --
	// must fail open (return false) AND be logged, not swallowed
	// identically to the ordinary "never revoked" case.
	if r.IsRevoked("agent-abc123") {
		t.Error("expected IsRevoked to fail open (false) on a genuine query error")
	}
	if !strings.Contains(logBuf.String(), "revocation check failed open") {
		t.Errorf("expected a query error to be logged, got log output: %q", logBuf.String())
	}
}

func TestPostgresRevoker_IsRevoked_NotFoundIsNeverLogged(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	r, err := adapter.NewPostgresRevoker(dsn, logger)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	defer func() { _ = r.Close() }()

	if r.IsRevoked("never-revoked") {
		t.Error("expected an identity with no revocation entry to not be revoked")
	}
	if logBuf.Len() != 0 {
		t.Errorf("expected the ordinary not-found case to produce zero log output, got: %q", logBuf.String())
	}
}
