package adapter_test

import (
	"bytes"
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/scim/adapter"
)

// testSchema isolates this package's Postgres tests from every other
// package's real-Postgres tests (audit/adapter, credential/adapter,
// cmd/wardline all run against the same WARDLINE_TEST_POSTGRES_DSN
// database, and go test ./... schedules different packages' test
// binaries concurrently) -- without this, a DROP TABLE from one package
// can race a live query/insert from another against same-named tables in
// the shared "public" schema.
const testSchema = "wardline_test_scim"

// testDSN mirrors credential/adapter/postgres_revoker_test.go's helper of
// the same intent -- same skip behavior, same env var, same
// "point at a disposable database only" warning, plus search_path pinned
// to testSchema so every table this package's tests create or drop stays
// confined to it.
func testDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + testSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + testSchema
}

func dropSCIMBindingsTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS scim_group_bindings`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

// TestPostgresBindingStore_PersistsAcrossInstances is the actual HA/
// restart-survival scenario: two separate *PostgresBindingStore instances
// (simulating two replicas, or a restart) against the same DSN -- a
// binding set through one is seen by the other, proven against a real
// shared database, not just the same in-process struct.
func TestPostgresBindingStore_PersistsAcrossInstances(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	store1, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBindingStore (store1): %v", err)
	}
	defer func() { _ = store1.Close() }()
	store1.SetGroupMembers("wardline:tenant-acme:role-admin", []string{"alice"})

	store2, err := adapter.NewPostgresBindingStore(dsn, nil) // simulates a second replica reading the same table
	if err != nil {
		t.Fatalf("NewPostgresBindingStore (store2): %v", err)
	}
	defer func() { _ = store2.Close() }()

	_, scoped := store2.Bindings("alice")
	if len(scoped) != 1 || scoped[0].RoleName != "admin" {
		t.Fatalf("second store instance didn't see first instance's binding: %+v", scoped)
	}
}

func TestPostgresBindingStore_GlobalGroupYieldsClusterBinding(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	store, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBindingStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	store.SetGroupMembers("wardline:role-superadmin", []string{"bob"})

	cluster, scoped := store.Bindings("bob")
	if len(cluster) != 1 || cluster[0].RoleName != "superadmin" {
		t.Fatalf("expected a cluster binding for bob, got cluster=%+v scoped=%+v", cluster, scoped)
	}
	if len(scoped) != 0 {
		t.Fatalf("expected no scoped bindings for a global group, got %+v", scoped)
	}
}

func TestPostgresBindingStore_SetGroupMembersIgnoresUnrecognizedGroupName(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	store, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBindingStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	store.SetGroupMembers("Engineering", []string{"carol"}) // not a Wardline-recognized group name

	cluster, scoped := store.Bindings("carol")
	if len(cluster) != 0 || len(scoped) != 0 {
		t.Fatalf("expected an unrecognized group name to grant no bindings, got cluster=%+v scoped=%+v", cluster, scoped)
	}
}

func TestPostgresBindingStore_RemoveGroupRevokesMembership(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	store, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBindingStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	store.SetGroupMembers("wardline:tenant-acme:role-admin", []string{"alice"})
	store.RemoveGroup("wardline:tenant-acme:role-admin")

	_, scoped := store.Bindings("alice")
	if len(scoped) != 0 {
		t.Fatalf("expected RemoveGroup to revoke alice's binding, got %+v", scoped)
	}
}

func TestPostgresBindingStore_SetGroupMembersReplacesWholesale(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	store, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBindingStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	store.SetGroupMembers("wardline:tenant-acme:role-admin", []string{"alice", "bob"})
	store.SetGroupMembers("wardline:tenant-acme:role-admin", []string{"bob"}) // alice dropped

	_, scoped := store.Bindings("alice")
	if len(scoped) != 0 {
		t.Fatalf("expected alice's binding to be gone after replace, got %+v", scoped)
	}
	_, scoped = store.Bindings("bob")
	if len(scoped) != 1 {
		t.Fatalf("expected bob to still hold a binding, got %+v", scoped)
	}
}

func TestPostgresBindingStore_TableCreationIsIdempotent(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	store1, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("first NewPostgresBindingStore: %v", err)
	}
	defer func() { _ = store1.Close() }()

	store2, err := adapter.NewPostgresBindingStore(dsn, nil)
	if err != nil {
		t.Fatalf("second NewPostgresBindingStore (should be idempotent): %v", err)
	}
	defer func() { _ = store2.Close() }()
}

func TestNewPostgresBindingStore_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresBindingStore("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable", nil)
	if err == nil {
		t.Fatal("expected an error constructing a binding store against an unreachable database")
	}
}

// TestPostgresBindingStore_SetGroupMembersAgainstClosedPoolIsLogged proves
// SetGroupMembers' write failure isn't silently swallowed when a logger
// is wired in -- it has no error return (matching the in-memory
// BindingStore's error-free signature), so a logged warning is the only
// way an operator can tell a provisioning write never took effect.
func TestPostgresBindingStore_SetGroupMembersAgainstClosedPoolIsLogged(t *testing.T) {
	dsn := testDSN(t)
	dropSCIMBindingsTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	store, err := adapter.NewPostgresBindingStore(dsn, logger)
	if err != nil {
		t.Fatalf("NewPostgresBindingStore: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store.SetGroupMembers("wardline:tenant-acme:role-admin", []string{"alice"}) // write against a closed pool

	if !strings.Contains(logBuf.String(), "scim binding store write failed") {
		t.Errorf("expected a write failure against a closed pool to be logged, got: %q", logBuf.String())
	}
}
