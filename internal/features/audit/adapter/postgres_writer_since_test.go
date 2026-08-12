package adapter_test

import (
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

// TestPostgresWriter_Since_ReturnsOnlyNewerEntriesInOrder is Since's
// basic contract: rows with id > afterID, oldest first.
func TestPostgresWriter_Since_ReturnsOnlyNewerEntriesInOrder(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	w, err := adapter.NewPostgresWriter(db)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}

	for _, tool := range []string{"read_file", "write_file", "list_dir"} {
		if err := w.Write(domain.Entry{Timestamp: time.Now(), Identity: "alice", Tenant: "acme", Tool: tool, Decision: "allow"}); err != nil {
			t.Fatalf("Write(%q): %v", tool, err)
		}
	}

	all, err := w.Since(0, 10, "")
	if err != nil {
		t.Fatalf("Since(0, ...): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries from id 0, got %d", len(all))
	}
	if all[0].Tool != "read_file" || all[1].Tool != "write_file" || all[2].Tool != "list_dir" {
		t.Errorf("expected oldest-first order, got %+v", all)
	}

	newer, err := w.Since(all[0].ID, 10, "")
	if err != nil {
		t.Fatalf("Since(all[0].ID, ...): %v", err)
	}
	if len(newer) != 2 || newer[0].Tool != "write_file" {
		t.Errorf("expected only the 2 entries newer than the first, got %+v", newer)
	}
}

// TestPostgresWriter_Since_FiltersByTenant proves the cluster-wide live
// view can still be scoped per-tenant (the same tenant-filter contract
// dashboardusecase.RingBuffer.Since already has).
func TestPostgresWriter_Since_FiltersByTenant(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	w, err := adapter.NewPostgresWriter(db)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}

	if err := w.Write(domain.Entry{Timestamp: time.Now(), Identity: "alice", Tenant: "acme", Tool: "x", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(domain.Entry{Timestamp: time.Now(), Identity: "bob", Tenant: "widgets-inc", Tool: "y", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}

	acmeOnly, err := w.Since(0, 10, "acme")
	if err != nil {
		t.Fatalf("Since(..., \"acme\"): %v", err)
	}
	if len(acmeOnly) != 1 || acmeOnly[0].Tenant != "acme" {
		t.Errorf("expected exactly 1 acme entry, got %+v", acmeOnly)
	}
}

// TestPostgresWriter_Since_RespectsLimit mirrors
// RingBuffer.Since's own limit contract.
func TestPostgresWriter_Since_RespectsLimit(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	w, err := adapter.NewPostgresWriter(db)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}

	for range 5 {
		if err := w.Write(domain.Entry{Timestamp: time.Now(), Identity: "alice", Tenant: "acme", Tool: "x", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}

	limited, err := w.Since(0, 2, "")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected exactly 2 entries with limit=2, got %d", len(limited))
	}
}

// TestPostgresWriter_Since_EmptyTableReturnsEmptySlice covers the
// no-real-Postgres-data-yet case: no error, no rows.
func TestPostgresWriter_Since_EmptyTableReturnsEmptySlice(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	db := openTestPool(t, dsn)
	defer func() { _ = db.Close() }()
	w, err := adapter.NewPostgresWriter(db)
	if err != nil {
		t.Fatalf("NewPostgresWriter: %v", err)
	}

	out, err := w.Since(0, 10, "")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 entries from an empty table, got %d", len(out))
	}
}

// TestPostgresWriter_Since_CrossInstanceVisibility is the actual point
// of this feature: two separate *PostgresWriter instances (simulating
// two replicas) against the same DSN -- an entry written through one is
// visible via Since through the OTHER, proving the cluster-wide
// aggregation this feature exists for, against a real shared database,
// not just the same in-process struct.
func TestPostgresWriter_Since_CrossInstanceVisibility(t *testing.T) {
	dsn := testDSN(t)
	dropTable(t, dsn)

	dbA := openTestPool(t, dsn)
	defer func() { _ = dbA.Close() }()
	replicaA, err := adapter.NewPostgresWriter(dbA)
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}

	dbB := openTestPool(t, dsn)
	defer func() { _ = dbB.Close() }()
	replicaB, err := adapter.NewPostgresWriter(dbB)
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}

	if err := replicaA.Write(domain.Entry{Timestamp: time.Now(), Identity: "alice", Tenant: "acme", Tool: "written-by-a", Decision: "allow"}); err != nil {
		t.Fatalf("Write via replicaA: %v", err)
	}

	seenByB, err := replicaB.Since(0, 10, "")
	if err != nil {
		t.Fatalf("Since via replicaB: %v", err)
	}
	found := false
	for _, e := range seenByB {
		if e.Tool == "written-by-a" {
			found = true
		}
	}
	if !found {
		t.Error("expected replicaB's Since to see an entry written through replicaA -- if this fails, cluster-wide live-audit aggregation is not actually working end to end")
	}
}
