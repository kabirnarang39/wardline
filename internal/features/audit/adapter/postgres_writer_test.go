package adapter_test

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// testDSN returns the DSN to test against, skipping the test if no real
// Postgres is available. Start one locally with:
//
//	docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=wardline postgres:16
//
// and set WARDLINE_TEST_POSTGRES_DSN=postgres://postgres:wardline@localhost:5432/postgres?sslmode=disable
//
// WARNING: these tests DROP the audit_entries table at whatever DSN
// WARDLINE_TEST_POSTGRES_DSN points at (see dropTable below). Point this
// at a disposable database only — never at a real/shared one.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres integration test")
	}
	return dsn
}

// dropTable removes the table between tests so each test starts clean —
// tests share one real database (no per-test schema/database isolation
// this cycle), so this keeps them independent of run order.
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
