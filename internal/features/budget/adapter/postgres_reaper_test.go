package adapter

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
)

// reaperTestSchema is the same schema postgres_limiter_test.go uses --
// same package directory means one test binary and sequential execution,
// so sharing it is safe and keeps all budget Postgres test state in one
// place.
const reaperTestSchema = "wardline_test_budget"

// reaperTestDSN mirrors postgres_limiter_test.go's budgetTestDSN, which
// this file cannot call: this test is white-box (package adapter, not
// adapter_test) so it can reference budgetReapInterval and reach l.db for
// row counts, exactly like inmemory_eviction_test.go is white-box to reach
// l.buckets.
func reaperTestDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + reaperTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS ` + reaperTestSchema + `.budget_buckets`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + reaperTestSchema
}

// TestPostgresLimiter_ReapsExpiredRowsOnSweep is the Postgres mirror of
// TestInMemoryLimiter_EvictsExpiredBucketsOnSweep, and proves the same
// property against a real database: every distinct identity that ever
// calls once leaves a row, and without the sweep budget_buckets grows
// without bound. Structured identically — phase 1 creates
// budgetReapInterval never-revisited rows, phase 2 drives the next sweep
// boundary from a single different identity after the window has passed,
// so any disappearance can only be the sweep (never the per-row
// reset-on-touch path, which requires the row to be touched).
func TestPostgresLimiter_ReapsExpiredRowsOnSweep(t *testing.T) {
	dsn := reaperTestDSN(t)

	// requestsPerWindow is far above the call counts below so no call is
	// ever denied — this test is about row lifetime, not admission.
	db, err := pgpool.Open(dsn, 0)
	if err != nil {
		t.Fatalf("pgpool.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	l, err := NewPostgresLimiter(db, 100000, time.Second, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}

	countRows := func() int {
		var n int
		if err := l.db.QueryRow(`SELECT COUNT(*) FROM budget_buckets`).Scan(&n); err != nil {
			t.Fatalf("count budget_buckets: %v", err)
		}
		return n
	}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < budgetReapInterval; i++ {
		l.Allow(fmt.Sprintf("stale-%d", i), "", "", now)
	}
	// The final call of this loop lands exactly on a sweep boundary, but
	// every row's window starts at `now`, so nothing is expired yet and
	// all rows must survive.
	if got := countRows(); got != budgetReapInterval {
		t.Fatalf("expected %d rows after phase 1, got %d", budgetReapInterval, got)
	}

	later := now.Add(2 * time.Second)
	for i := 0; i < budgetReapInterval; i++ {
		l.Allow("same-id", "", "", later)
	}

	if got := countRows(); got != 1 {
		t.Fatalf("expected the sweep to delete all %d expired rows, leaving only same-id's; got %d rows", budgetReapInterval, got)
	}
	var key string
	if err := l.db.QueryRow(`SELECT key FROM budget_buckets`).Scan(&key); err != nil {
		t.Fatalf("read surviving row: %v", err)
	}
	if !strings.Contains(key, "same-id") {
		t.Errorf("expected same-id's own (still live) row to survive the sweep, got key %q", key)
	}
}
