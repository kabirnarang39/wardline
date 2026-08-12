package adapter_test

import (
	"database/sql"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/adapter"
	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set; skipping Postgres integration test")
	}
	return dsn
}

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

func dropCostBudgetTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`DROP TABLE IF EXISTS cost_budget_counters`)
	require.NoError(t, err)
}

func TestPostgresMeter_AddsAndPersistsAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	dropCostBudgetTable(t, dsn)

	db1 := openTestPool(t, dsn)
	defer func() { _ = db1.Close() }()
	m1, err := adapter.NewPostgresMeter(db1, testLogger)
	require.NoError(t, err)
	t1, err := m1.Add("job-1", 30, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 30, t1)

	db2 := openTestPool(t, dsn)
	defer func() { _ = db2.Close() }()
	m2, err := adapter.NewPostgresMeter(db2, testLogger)
	require.NoError(t, err)
	t2, err := m2.Add("job-1", 20, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 50, t2)
}

func TestPostgresMeter_KeysIndependent(t *testing.T) {
	dsn := testDSN(t)
	dropCostBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)
	_, _ = m.Add("job-a", 10, time.Now())
	total, err := m.Add("job-b", 5, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 5, total)
}

func TestPostgresMeter_CurrentDoesNotAdd(t *testing.T) {
	dsn := testDSN(t)
	dropCostBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)
	total, err := m.Current("never-seen", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	_, _ = m.Add("job-x", 20, time.Now())
	total, err = m.Current("job-x", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 20, total)
}

func TestPostgresMeter_ConcurrentAddsAreAtomic(t *testing.T) {
	dsn := testDSN(t)
	dropCostBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := m.Add("job-concurrent", 1, time.Now())
			errs <- err
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
	final, err := m.Add("job-concurrent", 0, time.Now())
	require.NoError(t, err)
	assert.Equal(t, n, final)
}

func TestPostgresMeter_ListNearCeiling_SortsByTotalDescendingAndLimits(t *testing.T) {
	dsn := testDSN(t)
	dropCostBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)
	_, _ = m.Add("low", 1, time.Now())
	_, _ = m.Add("high", 30, time.Now())
	got := m.ListNearCeiling(1)
	assert.Equal(t, []domain.Entry{{Key: "high", Total: 30}}, got)
}
