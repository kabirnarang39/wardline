package adapter_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// testSchema isolates this package's Postgres tests from every other
// package's (internal/features/credential/adapter and cmd/wardline both
// run their own real-Postgres tests against the same
// WARDLINE_TEST_POSTGRES_DSN-pointed database, and go test ./...
// schedules different packages' test binaries concurrently) -- without
// this, a DROP TABLE from one package can race a live query/insert from
// another against tables of the same name in the shared "public" schema.
const testSchema = "wardline_test_audit"

// testDSN returns the DSN to test against, skipping the test if no real
// Postgres is available, with search_path pinned to testSchema so every
// table this package's tests create or drop stays confined to it. Start
// a real Postgres locally with:
//
//	docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=wardline postgres:16
//
// and set WARDLINE_TEST_POSTGRES_DSN=postgres://postgres:wardline@localhost:5432/postgres?sslmode=disable
//
// WARNING: these tests DROP the audit_entries table within testSchema
// (see dropTable below). Point WARDLINE_TEST_POSTGRES_DSN at a
// disposable database only — never at a real/shared one.
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

// dropTable removes the table between tests so each test starts clean —
// scoped to testSchema, so it can never touch another package's tables
// of the same name.
func dropTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_entries`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func TestPostgresWriter_CreatesTableAndWrites(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	entry := domain.Entry{
		Timestamp: now,
		Identity:  "agent-1",
		Tool:      "read_file",
		Decision:  "allow",
		LatencyMS: 5,
		Reason:    "",
		TraceID:   "trace-abc",
	}
	if err := w.Write(entry); err != nil {
		t.Fatalf("Write: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for verification: %v", err)
	}
	defer func() { _ = db.Close() }()

	var identity, tool, decision, traceID string
	var latencyMS int64
	row := db.QueryRow(`SELECT identity, tool, decision, latency_ms, trace_id FROM audit_entries LIMIT 1`)
	if err := row.Scan(&identity, &tool, &decision, &latencyMS, &traceID); err != nil {
		t.Fatalf("verify insert: %v", err)
	}
	if identity != "agent-1" || tool != "read_file" || decision != "allow" || latencyMS != 5 || traceID != "trace-abc" {
		t.Errorf("unexpected row: identity=%s tool=%s decision=%s latency=%d trace=%s", identity, tool, decision, latencyMS, traceID)
	}
}

func TestPostgresWriter_TableCreationIsIdempotent(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w1, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("first NewPostgresWriter: %v", err)
	}
	defer func() { _ = w1.Close() }()

	// Simulates a second Wardline instance starting against the same
	// already-initialized database — must not error.
	w2, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("second NewPostgresWriter (should be idempotent): %v", err)
	}
	defer func() { _ = w2.Close() }()
}

func TestNewPostgresWriter_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresWriter("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable")
	if err == nil {
		t.Fatal("expected an error constructing a writer against an unreachable database")
	}
}

func TestPostgresWriter_WriteOnClosedConnectionReturnsError(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = w.Write(domain.Entry{Timestamp: time.Now(), Identity: "x", Tool: "y", Decision: "allow"})
	if err == nil {
		t.Fatal("expected Write on a closed writer to return an error, not panic or succeed")
	}
}

func TestPostgresWriter_QueryReturnsEntriesInRangeOrderedByTimestamp(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	entries := []domain.Entry{
		{Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Identity: "at-from", Tool: "read_file", Decision: "allow", LatencyMS: 1},
		{Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), Identity: "middle", Tool: "read_file", Decision: "deny", LatencyMS: 2, Reason: "denied by policy", TraceID: "trace-1"},
		{Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Identity: "at-to", Tool: "read_file", Decision: "allow", LatencyMS: 3},
	}
	for _, e := range entries {
		if err := w.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	got, err := w.Query(context.Background(),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (from-inclusive, to-exclusive), got %d: %+v", len(got), got)
	}
	if got[0].Identity != "at-from" || got[1].Identity != "middle" {
		t.Fatalf("expected [at-from, middle] ordered by timestamp, got %+v", got)
	}
	if got[1].Reason != "denied by policy" || got[1].TraceID != "trace-1" {
		t.Errorf("expected nullable columns (reason, trace_id) to round-trip, got %+v", got[1])
	}
}

func TestPostgresWriter_PurgeDeletesOnlyEntriesOlderThanCutoff(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	entries := []domain.Entry{
		{Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Identity: "old", Tool: "read_file", Decision: "allow"},
		{Timestamp: time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), Identity: "at-cutoff", Tool: "read_file", Decision: "allow"},
		{Timestamp: time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC), Identity: "recent", Tool: "read_file", Decision: "allow"},
	}
	for _, e := range entries {
		if err := w.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	cutoff := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	deleted, err := w.Purge(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected exactly 1 deleted row (only the one strictly before cutoff), got %d", deleted)
	}

	remaining, err := w.Query(context.Background(), time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Query after Purge: %v", err)
	}
	if len(remaining) != 2 || remaining[0].Identity != "at-cutoff" || remaining[1].Identity != "recent" {
		t.Fatalf("expected [at-cutoff, recent] to survive, got %+v", remaining)
	}
}

func TestPostgresWriter_PurgeNothingToDeleteReturnsZero(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	deleted, err := w.Purge(context.Background(), time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted rows on an empty table, got %d", deleted)
	}
}

// TestPostgresWriter_MissingTenantDefaultsOnRead proves the migration is
// safe against a table that predates this task: it hand-creates the
// pre-Task-20 schema (no tenant column) and inserts a row directly, the
// same shape a deployment upgrading in place would have on disk, then
// constructs a PostgresWriter (which must run the additive migration
// against that already-populated table) and confirms the legacy row
// reads back with Tenant defaulted, never empty.
func TestPostgresWriter_MissingTenantDefaultsOnRead(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open to seed legacy schema: %v", err)
	}
	if _, err := db.Exec(`
CREATE TABLE audit_entries (
	id BIGSERIAL PRIMARY KEY,
	timestamp TIMESTAMPTZ NOT NULL,
	identity TEXT NOT NULL,
	tool TEXT NOT NULL,
	decision TEXT NOT NULL,
	latency_ms BIGINT NOT NULL,
	reason TEXT,
	trace_id TEXT
)`); err != nil {
		t.Fatalf("create pre-Task-20 schema: %v", err)
	}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := db.Exec(
		`INSERT INTO audit_entries (timestamp, identity, tool, decision, latency_ms) VALUES ($1, $2, $3, $4, $5)`,
		ts, "legacy-agent", "read_file", "allow", 5,
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding connection: %v", err)
	}

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter (must migrate the pre-existing table): %v", err)
	}
	defer func() { _ = w.Close() }()

	got, err := w.Query(context.Background(), ts.Add(-time.Hour), ts.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].Tenant != tenant.Default {
		t.Fatalf("got %+v, want one entry with Tenant=%q", got, tenant.Default)
	}
}

func TestPostgresWriter_QueryEmptyRangeReturnsNoRows(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	w, err := adapter.NewPostgresWriter(dsn)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	got, err := w.Query(context.Background(), time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no entries, got %+v", got)
	}
}
