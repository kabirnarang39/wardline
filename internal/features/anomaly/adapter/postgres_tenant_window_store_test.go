package adapter_test

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
)

const tenantAnomalyTestSchema = "wardline_test_tenant_anomaly"

// tenantAnomalyTestDSN mirrors baselineTestDSN's exact isolation
// pattern (postgres_baseline_store_test.go): a dedicated schema per
// feature area so this file's tables never collide with any other
// test file's, real Postgres or not.
func tenantAnomalyTestDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + tenantAnomalyTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + tenantAnomalyTestSchema
}

func dropTenantWindowTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS tenant_window_totals`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func TestPostgresTenantWindowStore_AddAndGet_MergesAcrossInstances(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	dropTenantWindowTable(t, dsn)
	s1, err := adapter.NewPostgresTenantWindowStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresTenantWindowStore (store 1): %v", err)
	}
	defer func() { _ = s1.Close() }()
	s2, err := adapter.NewPostgresTenantWindowStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresTenantWindowStore (store 2): %v", err)
	}
	defer func() { _ = s2.Close() }()

	windowStart := time.Now().Truncate(time.Minute)
	tenant := "cross-instance-test-tenant"

	// Simulates two replicas, each contributing their own local
	// window's total for the identical window, in turn.
	got1, err := s1.AddAndGet(tenant, windowStart, 300)
	if err != nil {
		t.Fatalf("AddAndGet (store 1): %v", err)
	}
	if got1 != 300 {
		t.Fatalf("expected first contribution to read back 300, got %d", got1)
	}

	got2, err := s2.AddAndGet(tenant, windowStart, 450)
	if err != nil {
		t.Fatalf("AddAndGet (store 2): %v", err)
	}
	if got2 != 750 {
		t.Fatalf("expected the second store's read to see the FIRST store's contribution merged in (300+450=750), got %d -- if this is 450, the two stores aren't sharing state", got2)
	}

	// A different window must not see this window's total.
	otherWindow := windowStart.Add(time.Minute)
	got3, err := s1.AddAndGet(tenant, otherWindow, 10)
	if err != nil {
		t.Fatalf("AddAndGet (store 1, other window): %v", err)
	}
	if got3 != 10 {
		t.Fatalf("expected a different window to start fresh at 10, got %d (windows are bleeding into each other)", got3)
	}
}

func TestPostgresTenantWindowStore_FailsFastOnBadDSN(t *testing.T) {
	_, err := adapter.NewPostgresTenantWindowStore("postgres://bad:bad@localhost:1/nonexistent", nil)
	if err == nil {
		t.Fatal("expected NewPostgresTenantWindowStore to fail on an unreachable DSN, not silently succeed")
	}
}

func TestPostgresTenantWindowStore_TableCreationIsIdempotent(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	if _, err := adapter.NewPostgresTenantWindowStore(dsn, nil); err != nil {
		t.Fatalf("first NewPostgresTenantWindowStore: %v", err)
	}
	if _, err := adapter.NewPostgresTenantWindowStore(dsn, nil); err != nil {
		t.Fatalf("second NewPostgresTenantWindowStore (CREATE TABLE IF NOT EXISTS should be a no-op): %v", err)
	}
}
