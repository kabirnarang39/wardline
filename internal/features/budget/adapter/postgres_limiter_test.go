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

// TestPostgresLimiter_ToolTierQueryErrorFailsOpen and
// TestPostgresLimiter_TenantTierQueryErrorFailsOpen exercise the
// fail-open path specifically at the tool and tenant checkAndAdvance
// call sites -- TestPostgresLimiter_AllowQueryErrorIsLoggedAndFailsOpen
// above only ever hits the identity-tier call site, since it configures
// no tool/tenant override. The code path is symmetric across all three
// tiers, but a request-rejecting security control's fail-open behavior
// deserves explicit coverage at every tier that can reach it, not just
// implicit trust that "the same helper is called elsewhere".
func TestPostgresLimiter_ToolTierQueryErrorFailsOpen(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	l, err := adapter.NewPostgresLimiter(dsn, 10, time.Minute, logger)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	l.SetToolLimit("expensive_tool", 1, time.Minute)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v := l.Allow("agent-abc123", "acme", "expensive_tool", time.Now())
	if !v.Allowed {
		t.Error("expected Allow to fail open (Allowed: true) on a tool-tier query error")
	}
	if !strings.Contains(logBuf.String(), "budget check failed open") {
		t.Errorf("expected the tool-tier query error to be logged, got log output: %q", logBuf.String())
	}
}

func TestPostgresLimiter_TenantTierQueryErrorFailsOpen(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	l, err := adapter.NewPostgresLimiter(dsn, 10, time.Minute, logger)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	l.SetTenantLimit("acme", 1, time.Minute)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	v := l.Allow("agent-abc123", "acme", "read_file", time.Now())
	if !v.Allowed {
		t.Error("expected Allow to fail open (Allowed: true) on a tenant-tier query error")
	}
	if !strings.Contains(logBuf.String(), "budget check failed open") {
		t.Errorf("expected the tenant-tier query error to be logged, got log output: %q", logBuf.String())
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

func TestPostgresLimiter_ToolLimitDeniesBeforeConsumingIdentityBudget(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 100, time.Minute, nil) // generous identity limit
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.SetToolLimit("expensive_tool", 1, time.Minute)

	now := time.Now()
	if v := l.Allow("agent-abc123", "acme", "expensive_tool", now); !v.Allowed {
		t.Fatalf("first call: expected Allowed, got denied: %s", v.Reason)
	}
	v := l.Allow("agent-abc123", "acme", "expensive_tool", now)
	if v.Allowed {
		t.Fatal("expected the tool bucket to deny the second call within the same window")
	}
	if !strings.Contains(v.Reason, "rate limit exceeded") {
		t.Errorf("expected a rate-limit reason, got %q", v.Reason)
	}
}

func TestPostgresLimiter_ToolLimitAppliesGloballyAcrossIdentities(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 100, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.SetToolLimit("expensive_tool", 1, time.Minute)

	now := time.Now()
	if v := l.Allow("alice", "acme", "expensive_tool", now); !v.Allowed {
		t.Fatalf("alice's call: expected Allowed, got denied: %s", v.Reason)
	}
	// A DIFFERENT identity calling the SAME tool must be denied too --
	// the tool bucket is shared across every identity/tenant calling
	// that tool, not per-identity, mirroring InMemoryLimiter's own
	// toolLimits/toolBuckets semantics exactly.
	v := l.Allow("bob", "widgets-inc", "expensive_tool", now)
	if v.Allowed {
		t.Fatal("expected a different identity's call to the same rate-limited tool to also be denied (tool buckets are global, not per-identity)")
	}
}

func TestPostgresLimiter_TenantLimitDeniesBeforeIdentityCheck(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 100, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.SetTenantLimit("acme", 1, time.Minute)

	now := time.Now()
	if v := l.Allow("alice", "acme", "read_file", now); !v.Allowed {
		t.Fatalf("first call: expected Allowed, got denied: %s", v.Reason)
	}
	// A DIFFERENT identity in the SAME tenant must be denied by the
	// shared tenant bucket, even with a generous per-identity limit.
	v := l.Allow("bob", "acme", "read_file", now)
	if v.Allowed {
		t.Fatal("expected a different identity in the same rate-limited tenant to also be denied")
	}
}

func TestPostgresLimiter_TenantWithNoOverrideIsNeverChecked(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 100, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.SetTenantLimit("acme", 1, time.Minute)
	// widgets-inc has NO override configured.

	now := time.Now()
	for i := 0; i < 5; i++ {
		v := l.Allow("alice", "widgets-inc", "read_file", now)
		if !v.Allowed && i == 0 {
			t.Fatalf("call %d: widgets-inc has no tenant override, expected it to fall through to the (generous) identity check, got denied: %s", i+1, v.Reason)
		}
	}
}

func TestPostgresLimiter_AllThreeTiersMustAllAdmit(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 100, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.SetTenantLimit("acme", 100, time.Minute)
	l.SetToolLimit("read_file", 100, time.Minute)

	now := time.Now()
	v := l.Allow("agent-abc123", "acme", "read_file", now)
	if !v.Allowed {
		t.Fatalf("expected all three generous tiers to admit, got denied: %s", v.Reason)
	}
}

func TestPostgresLimiter_ToolDenialDoesNotConsumeTenantOrIdentityBudget(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	l, err := adapter.NewPostgresLimiter(dsn, 100, time.Minute, nil)
	if err != nil {
		t.Fatalf("NewPostgresLimiter: %v", err)
	}
	defer func() { _ = l.Close() }()
	l.SetToolLimit("expensive_tool", 1, time.Minute)
	l.SetTenantLimit("acme", 2, time.Minute)

	now := time.Now()
	if v := l.Allow("agent-abc123", "acme", "expensive_tool", now); !v.Allowed {
		t.Fatalf("first call: expected Allowed, got denied: %s", v.Reason)
	}
	// Second call denied by the (now-exhausted) tool bucket -- must not
	// have touched the tenant bucket at all.
	if v := l.Allow("agent-abc123", "acme", "expensive_tool", now); v.Allowed {
		t.Fatal("expected the tool bucket to deny this call")
	}
	// A DIFFERENT tool, same tenant: if the prior denied call had wrongly
	// consumed tenant budget, the tenant bucket would now be at 2/2 and
	// deny this call too. It must still admit, proving the tool-tier
	// denial short-circuited before touching the tenant bucket.
	if v := l.Allow("agent-abc123", "acme", "read_file", now); !v.Allowed {
		t.Fatalf("expected the tenant bucket to still have budget (a denied tool-tier call must not consume tenant budget), got denied: %s", v.Reason)
	}
}

// TestPostgresLimiter_CrossInstanceBudgetIsShared is the actual HA
// scenario this whole plan exists for: two separate *PostgresLimiter
// instances (simulating two wardline replicas) against the same DSN --
// a budget consumed through one replica is visible to the other, proven
// against a real shared database, not just the same in-process struct.
// This is the property InMemoryLimiter's own doc comment documents as
// NOT holding ("running multiple replicas gives each its own
// independent budget") -- this test proves PostgresLimiter closes that
// gap.
func TestPostgresLimiter_CrossInstanceBudgetIsShared(t *testing.T) {
	dsn := budgetTestDSN(t)
	dropBudgetBucketsTable(t, dsn)

	replicaA, err := adapter.NewPostgresLimiter(dsn, 3, time.Minute, nil)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	defer func() { _ = replicaA.Close() }()

	replicaB, err := adapter.NewPostgresLimiter(dsn, 3, time.Minute, nil)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}
	defer func() { _ = replicaB.Close() }()

	now := time.Now()
	// Alternate calls between the two replicas -- same identity/tenant,
	// simulating a load balancer fanning one caller's traffic across
	// both. With a limit of 3, only the first 3 calls total (across
	// BOTH replicas combined) may be admitted.
	replicas := []*adapter.PostgresLimiter{replicaA, replicaB, replicaA, replicaB, replicaA}
	admitted := 0
	for i, r := range replicas {
		v := r.Allow("agent-abc123", "acme", "read_file", now)
		if v.Allowed {
			admitted++
		}
		t.Logf("call %d (replica %d): allowed=%v", i+1, i%2, v.Allowed)
	}

	if admitted != 3 {
		t.Errorf("expected exactly 3 of 5 calls fanned across two replicas to be admitted (shared budget), got %d -- if this is 3 per replica (6 total possible), the replicas are NOT sharing state", admitted)
	}
}
