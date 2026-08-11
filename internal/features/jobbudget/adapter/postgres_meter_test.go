package adapter_test

import (
	"database/sql"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/adapter"
	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
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

func dropJobBudgetTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	_, err = db.Exec(`DROP TABLE IF EXISTS job_budget_counters`)
	require.NoError(t, err)
}

func TestPostgresMeter_IncrementsAndPersistsAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)

	db1 := openTestPool(t, dsn)
	defer func() { _ = db1.Close() }()
	m1, err := adapter.NewPostgresMeter(db1, testLogger)
	require.NoError(t, err)
	c1, err := m1.Increment("job-1", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, c1)

	// A second Meter instance, with its own pool (simulating a second
	// replica), against the same DSN sees the same running count --
	// proves cross-replica sharing, the reason Postgres backing exists at
	// all.
	db2 := openTestPool(t, dsn)
	defer func() { _ = db2.Close() }()
	m2, err := adapter.NewPostgresMeter(db2, testLogger)
	require.NoError(t, err)
	c2, err := m2.Increment("job-1", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 2, c2)
}

func TestPostgresMeter_KeysIndependent(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)
	_, _ = m.Increment("job-a", time.Now())
	c, err := m.Increment("job-b", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, c)
}

func TestPostgresMeter_CurrentDoesNotIncrement(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)

	c, err := m.Current("never-seen", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 0, c)

	_, _ = m.Increment("job-x", time.Now())
	_, _ = m.Increment("job-x", time.Now())
	c, err = m.Current("job-x", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 2, c)
	// Reading again must not change it.
	c, err = m.Current("job-x", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 2, c)
}

func TestPostgresMeter_ConcurrentIncrementsAreAtomic(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := m.Increment("job-concurrent", time.Now())
			errs <- err
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
	final, err := m.Increment("job-concurrent", time.Now())
	require.NoError(t, err)
	assert.Equal(t, n+1, final)
}

func TestPostgresMeter_ListNearCeiling_SortsByCountDescendingAndLimits(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)

	_, _ = m.Increment("low", time.Now())
	for i := 0; i < 3; i++ {
		_, _ = m.Increment("high", time.Now())
	}
	for i := 0; i < 2; i++ {
		_, _ = m.Increment("mid", time.Now())
	}

	got := m.ListNearCeiling(2)
	assert.Equal(t, []domain.Entry{{Key: "high", Count: 3}, {Key: "mid", Count: 2}}, got)
}

func TestPostgresMeter_ListNearCeiling_EmptyWhenNoCounts(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	m, err := adapter.NewPostgresMeter(db, testLogger)
	require.NoError(t, err)

	assert.Empty(t, m.ListNearCeiling(10))
}
