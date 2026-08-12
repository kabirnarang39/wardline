package adapter_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
)

// tenantAnomalyTestDSN and openTenantWindowTestPool (defined in
// postgres_tenant_window_store_test.go, same package) are reused here
// unchanged -- identity_churn_window_totals is a distinct table name
// from tenant_window_totals, so sharing the test schema/pool-opening
// helpers is safe: nothing collides.

func dropChurnWindowTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS identity_churn_window_totals`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func TestPostgresChurnWindowStore_AddAndGet_MergesAcrossInstances(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	dropChurnWindowTable(t, dsn)

	db1 := openTenantWindowTestPool(t, dsn)
	defer func() { _ = db1.Close() }()
	s1, err := adapter.NewPostgresChurnWindowStore(db1, nil)
	if err != nil {
		t.Fatalf("NewPostgresChurnWindowStore (store 1): %v", err)
	}

	db2 := openTenantWindowTestPool(t, dsn)
	defer func() { _ = db2.Close() }()
	s2, err := adapter.NewPostgresChurnWindowStore(db2, nil)
	if err != nil {
		t.Fatalf("NewPostgresChurnWindowStore (store 2): %v", err)
	}

	windowStart := time.Now().Truncate(time.Minute)
	tenant := "cross-instance-test-tenant"

	got1, err := s1.AddAndGet(tenant, windowStart, 20)
	if err != nil {
		t.Fatalf("AddAndGet (store 1): %v", err)
	}
	if got1 != 20 {
		t.Fatalf("expected first contribution to read back 20, got %d", got1)
	}

	got2, err := s2.AddAndGet(tenant, windowStart, 25)
	if err != nil {
		t.Fatalf("AddAndGet (store 2): %v", err)
	}
	if got2 != 45 {
		t.Fatalf("expected the second store's read to see the FIRST store's contribution merged in (20+25=45), got %d -- if this is 25, the two stores aren't sharing state", got2)
	}

	otherWindow := windowStart.Add(time.Minute)
	got3, err := s1.AddAndGet(tenant, otherWindow, 3)
	if err != nil {
		t.Fatalf("AddAndGet (store 1, other window): %v", err)
	}
	if got3 != 3 {
		t.Fatalf("expected a different window to start fresh at 3, got %d (windows are bleeding into each other)", got3)
	}
}

func TestPostgresChurnWindowStore_TableCreationIsIdempotent(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)

	db := openTenantWindowTestPool(t, dsn)
	defer func() { _ = db.Close() }()

	if _, err := adapter.NewPostgresChurnWindowStore(db, nil); err != nil {
		t.Fatalf("first NewPostgresChurnWindowStore: %v", err)
	}
	if _, err := adapter.NewPostgresChurnWindowStore(db, nil); err != nil {
		t.Fatalf("second NewPostgresChurnWindowStore (CREATE TABLE IF NOT EXISTS should be a no-op): %v", err)
	}
}
