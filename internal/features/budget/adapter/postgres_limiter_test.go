package adapter_test

import (
	"bytes"
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/budget/adapter"
)

const budgetTestSchema = "wardline_test_budget"

func budgetTestDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + budgetTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + budgetTestSchema
}

func dropBudgetBucketsTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS budget_buckets`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func TestPostgresLimiter_SequentialCallsAdmitUpToLimitThenDeny(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 3, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now()
	for i := 0; i < 3; i++ {
		v := l.Allow("agent-abc123", "acme", "read_file", now)
		if !v.Allowed {
			t.Fatalf("call %d: expected Allowed, got denied: %s", i+1, v.Reason)
		}
	}
	v := l.Allow("agent-abc123", "acme", "read_file", now)
	if v.Allowed {
		t.Fatal("expected the 4th call within the same window to be denied")
	}
	if v.RetryAfter <= 0 {
		t.Errorf("expected a positive RetryAfter on denial, got %s", v.RetryAfter)
	}
	// A denied call must not have consumed budget -- one more call
	// (still within the same window) must be denied identically, not
	// admitted because a prior denial incremented the count past what
	// admission tracking expects.
	v2 := l.Allow("agent-abc123", "acme", "read_file", now)
	if v2.Allowed {
		t.Fatal("expected a 5th call to still be denied (a denied call must not consume budget)")
	}
}

func TestPostgresLimiter_WindowExpiryResets(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 1, 200*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now()
	if v := l.Allow("agent-abc123", "acme", "read_file", now); !v.Allowed {
		t.Fatalf("first call: expected Allowed, got denied: %s", v.Reason)
	}
	if v := l.Allow("agent-abc123", "acme", "read_file", now); v.Allowed {
		t.Fatal("second call within the same window: expected denied")
	}
	later := now.Add(250 * time.Millisecond) // past the 200ms window
	if v := l.Allow("agent-abc123", "acme", "read_file", later); !v.Allowed {
		t.Fatalf("call after window expiry: expected Allowed (fresh window), got denied: %s", v.Reason)
	}
}

func TestPostgresLimiter_DifferentIdentitiesHaveIndependentBuckets(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 1, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now()
	if v := l.Allow("alice", "acme", "read_file", now); !v.Allowed {
		t.Fatalf("alice's first call: expected Allowed, got denied: %s", v.Reason)
	}
	if v := l.Allow("bob", "acme", "read_file", now); !v.Allowed {
		t.Fatalf("bob's first call: expected Allowed (independent bucket from alice), got denied: %s", v.Reason)
	}
}

func TestPostgresLimiter_SameIdentityDifferentTenantsHaveIndependentBuckets(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 1, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now()
	if v := l.Allow("alice", "acme", "read_file", now); !v.Allowed {
		t.Fatalf("acme's alice: expected Allowed, got denied: %s", v.Reason)
	}
	if v := l.Allow("alice", "widgets-inc", "read_file", now); !v.Allowed {
		t.Fatalf("widgets-inc's alice: expected Allowed (independent bucket, same identity string different tenant), got denied: %s", v.Reason)
	}
}

func TestPostgresLimiter_ConcurrentCallsNeverExceedLimit(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	const limit = 10
	const callers = 50
	l, err := adapter.NewPostgresLimiter(dsn, limit, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now()
	var mu sync.Mutex
	allowedCount := 0
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := l.Allow("concurrent-agent", "acme", "read_file", now)
			if v.Allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount != limit {
		t.Errorf("expected exactly %d of %d genuinely concurrent calls to be admitted, got %d", limit, callers, allowedCount)
	}
}

func TestPostgresLimiter_TableCreationIsIdempotent(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l1, err := adapter.NewPostgresLimiter(dsn, 10, time.Minute, nil)
	if err != nil {
		t.Fatalf("first NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l1.Close() }()

	l2, err := adapter.NewPostgresLimiter(dsn, 10, time.Minute, nil)
	if err != nil {
		t.Fatalf("second NewPostgresLimiter (should be idempotent): %v", err)
	}
	defer func() { _ = l2.Close() }()
}

func TestNewPostgresLimiter_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresLimiter("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable", 10, time.Minute, nil)
	if err == nil {
		t.Fatal("expected an error constructing a limiter against an unreachable database")
	}
}

func TestPostgresLimiter_AllowQueryErrorIsLoggedAndFailsOpen(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	l, err := adapter.NewPostgresLimiter(dsn, 10, time.Minute, logger)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Allow against a closed pool -- a real error, not a normal
	// within-budget result -- must fail open (Allowed: true) AND be
	// logged, not swallowed identically to the ordinary case.
	v := l.Allow("agent-abc123", "acme", "read_file", time.Now())
	if !v.Allowed {
		t.Error("expected Allow to fail open (Allowed: true) on a genuine query error")
	}
	if !strings.Contains(logBuf.String(), "budget check failed open") {
		t.Errorf("expected a query error to be logged, got log output: %q", logBuf.String())
	}
}

func TestPostgresLimiter_Allow_NoLoggerDoesNotPanicOnQueryError(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 10, time.Minute, nil) // nil logger
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v := l.Allow("agent-abc123", "acme", "read_file", time.Now()) // must not panic
	if !v.Allowed {
		t.Error("expected Allow to fail open even with a nil logger")
	}
}
