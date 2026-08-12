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
	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
)

// openTestPool opens a pool the same way cmd/wardline/main.go does (via
// pgpool.Open, shared across every Postgres-backed feature in production)
// -- test callers get the identical Open+Ping+pool-config path real
// traffic goes through, not a bespoke test-only shortcut.
func openTestPool(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := pgpool.Open(dsn, 0)
	if err != nil {
		t.Fatalf("openTestPool: %v", err)
	}
	return db
}

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

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	if err := r.Revoke("", "agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if !r.IsRevoked("", "agent-abc123") {
		t.Error("expected agent-abc123 to be revoked")
	}
}

func TestPostgresRevoker_UnrevokedIdentityIsNotRevoked(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	if r.IsRevoked("", "never-revoked") {
		t.Error("expected an identity with no revocation entry to not be revoked")
	}
}

func TestPostgresRevoker_ExpiredRevocationSelfHeals(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	if err := r.Revoke("", "agent-abc123", time.Now().Add(-time.Minute)); err != nil { // already expired
		t.Fatalf("Revoke: %v", err)
	}

	if r.IsRevoked("", "agent-abc123") {
		t.Error("expected an expired revocation to no longer count as revoked")
	}
}

func TestPostgresRevoker_TableCreationIsIdempotent(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db1 := openTestPool(t, dsn)
	defer func() { _ = db1.Close() }()
	_, err := adapter.NewPostgresRevoker(db1, nil)
	if err != nil {
		t.Fatalf("first NewPostgresRevoker: %v", err)
	}

	_, err = adapter.NewPostgresRevoker(db1, nil)
	if err != nil {
		t.Fatalf("second NewPostgresRevoker (should be idempotent): %v", err)
	}
}

// TestPostgresRevoker_CrossInstanceRevocationPropagates is the actual HA
// scenario: two separate *PostgresRevoker instances, each with its own
// connection pool (simulating two replicas, each running the ONE shared
// pool pgpool.Open builds for its own process) against the same DSN -- a
// revocation made through one is seen by the other, proven against a real
// shared database, not just the same in-process struct.
func TestPostgresRevoker_CrossInstanceRevocationPropagates(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	dbA := openTestPool(t, dsn)
	defer func() { _ = dbA.Close() }()
	replicaA, err := adapter.NewPostgresRevoker(dbA, nil)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}

	dbB := openTestPool(t, dsn)
	defer func() { _ = dbB.Close() }()
	replicaB, err := adapter.NewPostgresRevoker(dbB, nil)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}

	if err := replicaA.Revoke("", "agent-abc123", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if !replicaB.IsRevoked("", "agent-abc123") {
		t.Error("expected a revocation made through replicaA to be visible through replicaB (same Postgres database)")
	}
}

func TestPostgresRevoker_RevokeAgainstClosedPoolReturnsError(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := r.Revoke("", "agent-abc123", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected Revoke against a closed connection pool to return an error")
	}
}

func TestPostgresRevoker_IsRevoked_QueryErrorIsLoggedAndFailsOpen(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	db := openTestPool(t, dsn)
	r, err := adapter.NewPostgresRevoker(db, logger)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Query against a closed pool -- a real error, not sql.ErrNoRows --
	// must fail open (return false) AND be logged, not swallowed
	// identically to the ordinary "never revoked" case.
	if r.IsRevoked("", "agent-abc123") {
		t.Error("expected IsRevoked to fail open (false) on a genuine query error")
	}
	if !strings.Contains(logBuf.String(), "revocation check failed open") {
		t.Errorf("expected a query error to be logged, got log output: %q", logBuf.String())
	}
}

func TestPostgresRevoker_ScopedRevokeDoesNotAffectOtherTenant(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	now := time.Now()
	if err := r.Revoke("acme", "alice-pgtest", now.Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if !r.IsRevoked("acme", "alice-pgtest") {
		t.Error("expected acme's alice-pgtest to be revoked")
	}
	if r.IsRevoked("widgets-inc", "alice-pgtest") {
		t.Error("widgets-inc's alice-pgtest must not be revoked by acme's revoke")
	}
}

func TestPostgresRevoker_WildcardRevokeAffectsEveryTenant(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	now := time.Now()
	if err := r.Revoke("", "bob-pgtest", now.Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if !r.IsRevoked("acme", "bob-pgtest") {
		t.Error("wildcard revoke must deny acme's bob-pgtest")
	}
	if !r.IsRevoked("widgets-inc", "bob-pgtest") {
		t.Error("wildcard revoke must deny widgets-inc's bob-pgtest")
	}
}

// insertLegacyBareIdentityRow simulates a pre-migration row by inserting
// directly through its own connection, bypassing Revoke's key-composition
// logic entirely -- same pattern as dropRevokedIdentitiesTable, since
// package adapter_test has no access to PostgresRevoker's unexported db
// field or SQL constants.
func insertLegacyBareIdentityRow(t *testing.T, dsn, identity string, expiresAt time.Time) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for legacy row insert: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`INSERT INTO revoked_identities (identity, expires_at) VALUES ($1, $2)`, identity, expiresAt); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
}

func TestPostgresRevoker_LegacyBareIdentityRowStillDeniesEveryTenant(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	now := time.Now()
	insertLegacyBareIdentityRow(t, dsn, "carol-pgtest", now.Add(time.Hour))

	if !r.IsRevoked("acme", "carol-pgtest") {
		t.Error("legacy bare-identity row must deny acme's carol-pgtest")
	}
	if !r.IsRevoked("widgets-inc", "carol-pgtest") {
		t.Error("legacy bare-identity row must deny widgets-inc's carol-pgtest")
	}
}

// TestPostgresRevoker_LengthPrefixKeyEncodingAvoidsSeparatorCollision proves
// the fix for a real bug: an earlier version of postgresSafeKey joined
// tenant and identity with a single separator byte (first \x00, which
// Postgres's TEXT type rejects outright; then \x1f, which Postgres accepts
// but which a JWT claim -- an arbitrary JSON string with no charset
// restriction -- can legitimately contain). The fixture below uses values
// that actually collide under that real, previously-shipped \x1f-based
// join: tenant="a\x1f1", identity="b-pgtest" and tenant="a",
// identity="1\x1fb-pgtest" both produce the identical string
// "a\x1f1\x1fb-pgtest" under naive "tenant\x1fidentity" concatenation.
// (An earlier version of this fixture used a ":"-separator strawman --
// tenant="a", identity="1:b-pgtest" vs. tenant="a:1", identity="b-pgtest"
// -- which does NOT collide under the real \x1f-based old code, so it
// passed even against the actual bug and would stay green if
// postgresSafeKey ever regressed to any single-byte separator other than
// ":". I1's final-review fix-wave verification: reverting postgresSafeKey
// to the \x1f join makes THIS fixture fail; the length-prefixed encoding
// (fmt.Sprintf("%d:%s:%s", len(tenantName), ...)) keeps the two pairs
// distinct -- "3:a\x1f1:b-pgtest" vs. "1:a:1\x1fb-pgtest".
func TestPostgresRevoker_LengthPrefixKeyEncodingAvoidsSeparatorCollision(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, nil)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	now := time.Now()
	if err := r.Revoke("a\x1f1", "b-pgtest", now.Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if r.IsRevoked("a", "1\x1fb-pgtest") {
		t.Error(`tenant="a\x1f1", identity="b-pgtest" must not collide with tenant="a", identity="1\x1fb-pgtest"`)
	}
	if !r.IsRevoked("a\x1f1", "b-pgtest") {
		t.Error("expected the actual revoked pair to still be revoked")
	}
}

func TestPostgresRevoker_IsRevoked_NotFoundIsNeverLogged(t *testing.T) {
	dsn := testDSN(t)
	dropRevokedIdentitiesTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	r, err := adapter.NewPostgresRevoker(db, logger)
	if err != nil {
		t.Fatalf("NewPostgresRevoker: %v", err)
	}

	if r.IsRevoked("", "never-revoked") {
		t.Error("expected an identity with no revocation entry to not be revoked")
	}
	if logBuf.Len() != 0 {
		t.Errorf("expected the ordinary not-found case to produce zero log output, got: %q", logBuf.String())
	}
}
