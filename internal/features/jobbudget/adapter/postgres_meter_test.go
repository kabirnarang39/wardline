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

	m1, err := adapter.NewPostgresMeter(dsn, testLogger)
	require.NoError(t, err)
	c1, err := m1.Increment("job-1", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, c1)

	// A second Meter instance against the same DSN sees the same running
	// count -- proves cross-replica sharing, the reason Postgres backing
	// exists at all.
	m2, err := adapter.NewPostgresMeter(dsn, testLogger)
	require.NoError(t, err)
	c2, err := m2.Increment("job-1", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 2, c2)
}

func TestPostgresMeter_KeysIndependent(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	m, err := adapter.NewPostgresMeter(dsn, testLogger)
	require.NoError(t, err)
	_, _ = m.Increment("job-a", time.Now())
	c, err := m.Increment("job-b", time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, c)
}

func TestPostgresMeter_CurrentDoesNotIncrement(t *testing.T) {
	dsn := testDSN(t)
	dropJobBudgetTable(t, dsn)
	m, err := adapter.NewPostgresMeter(dsn, testLogger)
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
	m, err := adapter.NewPostgresMeter(dsn, testLogger)
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
