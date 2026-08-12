package adapter_test

import (
	"database/sql"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	"github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
)

// openTenantBaselineTestPool opens a pool the same way cmd/wardline/main.go
// does (via pgpool.Open, shared across every Postgres-backed feature in
// production) -- test callers get the identical Open+Ping+pool-config path
// real traffic goes through, not a bespoke test-only shortcut.
func openTenantBaselineTestPool(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := pgpool.Open(dsn, 0)
	if err != nil {
		t.Fatalf("openTenantBaselineTestPool: %v", err)
	}
	return db
}

func TestPostgresTenantBaselineStore_SaveAndLoad_RoundTrips(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	db := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	s, err := adapter.NewPostgresTenantBaselineStore(db, "test-instance-1", nil)
	if err != nil {
		t.Fatalf("NewPostgresTenantBaselineStore: %v", err)
	}

	snapshots := map[string]usecase.OnlineStatSnapshot{
		"tenant-a": {Mean: 597.5, M2: 12345.6, Count: 20},
		"tenant-b": {Mean: 30.1, M2: 88.2, Count: 8},
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

func TestPostgresTenantBaselineStore_DifferentInstancesDoNotShareRows(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	db1 := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db1.Close() }()
	s1, err := adapter.NewPostgresTenantBaselineStore(db1, "instance-1", nil)
	if err != nil {
		t.Fatalf("NewPostgresTenantBaselineStore (1): %v", err)
	}
	db2 := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db2.Close() }()
	s2, err := adapter.NewPostgresTenantBaselineStore(db2, "instance-2", nil)
	if err != nil {
		t.Fatalf("NewPostgresTenantBaselineStore (2): %v", err)
	}

	if err := s1.SaveAll(map[string]usecase.OnlineStatSnapshot{"only-on-1": {Mean: 1, M2: 1, Count: 1}}); err != nil {
		t.Fatalf("SaveAll (1): %v", err)
	}
	loaded2, err := s2.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll (2): %v", err)
	}
	if _, ok := loaded2["only-on-1"]; ok {
		t.Fatal("expected instance-2's LoadAll to NOT see instance-1's row -- baselines are per-instance restart-persistence, not cross-replica sharing (every replica converges via folding the SAME merged total, never by sharing baseline rows directly)")
	}
}

func TestPostgresTenantBaselineStore_SaveAllOnEmptyMapIsNoop(t *testing.T) {
	dsn := tenantAnomalyTestDSN(t)
	db := openTenantBaselineTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	s, err := adapter.NewPostgresTenantBaselineStore(db, "test-instance-empty", nil)
	if err != nil {
		t.Fatalf("NewPostgresTenantBaselineStore: %v", err)
	}

	if err := s.SaveAll(nil); err != nil {
		t.Fatalf("SaveAll(nil) should be a no-op, got error: %v", err)
	}
	if err := s.SaveAll(map[string]usecase.OnlineStatSnapshot{}); err != nil {
		t.Fatalf("SaveAll(empty map) should be a no-op, got error: %v", err)
	}
}
