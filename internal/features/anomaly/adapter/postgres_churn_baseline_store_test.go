package adapter_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

// tenantAnomalyTestDSN and openTenantBaselineTestPool (defined in
// postgres_tenant_window_store_test.go / postgres_tenant_baseline_store_test.go,
// same package) are reused here unchanged -- identity_churn_baselines is
// a distinct table name from tenant_baselines, so sharing the test
// schema/pool-opening helpers is safe: nothing collides.

func TestPostgresChurnBaselineStore_SaveAndLoad_RoundTrips(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	db := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	s, err := adapter.NewPostgresChurnBaselineStore(db, "test-instance-1", nil)
	if err != nil {
		t.Fatalf("NewPostgresChurnBaselineStore: %v", err)
	}

	snapshots := map[string]usecase.ChurnBaselineSnapshot{
		"tenant-a": {Mean: 2.5, M2: 12.6, Count: 20, CUSUM: 1.75},
		"tenant-b": {Mean: 1.1, M2: 3.2, Count: 8, CUSUM: 0},
	}
	if err := s.SaveAll(snapshots); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	for tenant, want := range snapshots {
		got, ok := loaded[tenant]
		if !ok {
			t.Errorf("expected tenant %q in loaded map, missing", tenant)
			continue
		}
		if got != want {
			t.Errorf("tenant %q: got %+v, want %+v", tenant, got, want)
		}
	}
}

func TestPostgresChurnBaselineStore_DifferentInstancesDoNotShareRows(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	db1 := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db1.Close() }()
	s1, err := adapter.NewPostgresChurnBaselineStore(db1, "churn-instance-1", nil)
	if err != nil {
		t.Fatalf("NewPostgresChurnBaselineStore (1): %v", err)
	}
	db2 := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db2.Close() }()
	s2, err := adapter.NewPostgresChurnBaselineStore(db2, "churn-instance-2", nil)
	if err != nil {
		t.Fatalf("NewPostgresChurnBaselineStore (2): %v", err)
	}

	if err := s1.SaveAll(map[string]usecase.ChurnBaselineSnapshot{"only-on-1": {Mean: 1, M2: 1, Count: 1, CUSUM: 0.5}}); err != nil {
		t.Fatalf("SaveAll (1): %v", err)
	}
	loaded2, err := s2.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll (2): %v", err)
	}
	if _, ok := loaded2["only-on-1"]; ok {
		t.Fatal("expected churn-instance-2's LoadAll to NOT see churn-instance-1's row -- baselines are per-instance restart-persistence, not cross-replica sharing")
	}
}

func TestPostgresChurnBaselineStore_SaveAllOnEmptyMapIsNoop(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	db := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	s, err := adapter.NewPostgresChurnBaselineStore(db, "test-instance-empty", nil)
	if err != nil {
		t.Fatalf("NewPostgresChurnBaselineStore: %v", err)
	}

	if err := s.SaveAll(nil); err != nil {
		t.Fatalf("SaveAll(nil) should be a no-op, got error: %v", err)
	}
	if err := s.SaveAll(map[string]usecase.ChurnBaselineSnapshot{}); err != nil {
		t.Fatalf("SaveAll(empty map) should be a no-op, got error: %v", err)
	}
}
