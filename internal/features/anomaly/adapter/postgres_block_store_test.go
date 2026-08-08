package adapter_test

import (
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
)

const blockTestSchema = "wardline_test_anomaly_block"

func blockTestDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + blockTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + blockTestSchema
}

func dropBlockedTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS blocked_identities`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func blockTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), nil))
}

func TestPostgresBlockStore_BlockThenCheckRoundTrips(t *testing.T) {
	dsn := blockTestDSN(t)
	dropBlockedTable(t, dsn)

	s, err := adapter.NewPostgresBlockStore(dsn, time.Hour, blockTestLogger())
	if err != nil {
		t.Fatalf("NewPostgresBlockStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	s.Block("agent-abc123", "acme", "ml_score anomaly")
	verdict := s.Check("agent-abc123", "acme", time.Now())
	if verdict.Allowed {
		t.Fatal("expected the blocked identity to be denied")
	}
	if verdict.Reason != "ml_score anomaly" {
		t.Errorf("expected the block reason to round-trip, got %q", verdict.Reason)
	}

	// A different identity is unaffected.
	if v := s.Check("someone-else", "acme", time.Now()); !v.Allowed {
		t.Error("expected an unblocked identity to be allowed")
	}
	// The same name in a different tenant is a distinct entry, unaffected.
	if v := s.Check("agent-abc123", "widgets-inc", time.Now()); !v.Allowed {
		t.Error("expected the same identity in a different tenant to be unblocked")
	}
}

func TestPostgresBlockStore_ExpiredBlockReadsAsUnblocked(t *testing.T) {
	dsn := blockTestDSN(t)
	dropBlockedTable(t, dsn)

	// A negative duration makes every block already-expired the instant
	// it's written, without a real sleep.
	s, err := adapter.NewPostgresBlockStore(dsn, -time.Hour, blockTestLogger())
	if err != nil {
		t.Fatalf("NewPostgresBlockStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	s.Block("agent-abc123", "acme", "expired immediately")
	if v := s.Check("agent-abc123", "acme", time.Now()); !v.Allowed {
		t.Error("expected an already-expired block to read as unblocked")
	}
}

// TestPostgresBlockStore_CrossReplica is the actual HA proof at the
// adapter level: a block written through one store instance is visible
// as blocked through a SECOND, independent store instance against the
// same DSN -- simulating two replicas sharing one database.
func TestPostgresBlockStore_CrossReplica(t *testing.T) {
	dsn := blockTestDSN(t)
	dropBlockedTable(t, dsn)

	replicaA, err := adapter.NewPostgresBlockStore(dsn, time.Hour, blockTestLogger())
	if err != nil {
		t.Fatalf("replicaA: %v", err)
	}
	defer func() { _ = replicaA.Close() }()
	replicaB, err := adapter.NewPostgresBlockStore(dsn, time.Hour, blockTestLogger())
	if err != nil {
		t.Fatalf("replicaB: %v", err)
	}
	defer func() { _ = replicaB.Close() }()

	replicaA.Block("agent-abc123", "acme", "blocked on replica A")
	if v := replicaB.Check("agent-abc123", "acme", time.Now()); v.Allowed {
		t.Fatal("expected a block written on replica A to be visible on replica B (shared postgres)")
	}
}

func TestPostgresBlockStore_UnblockRemovesActiveBlock(t *testing.T) {
	dsn := blockTestDSN(t)
	dropBlockedTable(t, dsn)

	s, err := adapter.NewPostgresBlockStore(dsn, time.Hour, blockTestLogger())
	if err != nil {
		t.Fatalf("NewPostgresBlockStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	s.Block("agent-abc123", "acme", "reason")
	if !s.Unblock("agent-abc123", "acme") {
		t.Fatal("expected Unblock to report an active block was removed")
	}
	if v := s.Check("agent-abc123", "acme", time.Now()); !v.Allowed {
		t.Error("expected the identity to be allowed after unblocking")
	}
	// Unblocking again reports false -- nothing active to remove.
	if s.Unblock("agent-abc123", "acme") {
		t.Error("expected a second Unblock to report nothing was active")
	}
}

func TestPostgresBlockStore_ListReturnsActiveBlocks(t *testing.T) {
	dsn := blockTestDSN(t)
	dropBlockedTable(t, dsn)

	s, err := adapter.NewPostgresBlockStore(dsn, time.Hour, blockTestLogger())
	if err != nil {
		t.Fatalf("NewPostgresBlockStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	s.Block("alice", "acme", "r1")
	s.Block("bob", "widgets-inc", "r2")

	all := s.List("")
	if len(all) != 2 {
		t.Fatalf("expected 2 active blocks unfiltered, got %d: %+v", len(all), all)
	}

	acme := s.List("acme")
	if len(acme) != 1 || acme[0].Identity != "alice" {
		t.Fatalf("expected only acme's block when filtered, got %+v", acme)
	}
}
