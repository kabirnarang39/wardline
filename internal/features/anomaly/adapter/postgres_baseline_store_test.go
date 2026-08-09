package adapter_test

import (
	"bytes"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/adapter"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

const baselineTestSchema = "wardline_test_anomaly_baseline"

// testInstanceID is the fixed instance ID passed to NewPostgresBaselineStore
// by every test in this file that doesn't specifically need a different
// one (see the cross-replica isolation test below, which uses two
// distinct instance IDs on purpose).
const testInstanceID = "test-instance"

func baselineTestDSN(t *testing.T) string {
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
	if _, err := db.Exec(`CREATE SCHEMA IF NOT EXISTS ` + baselineTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + baselineTestSchema
}

func dropBaselinesTable(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for cleanup: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`DROP TABLE IF EXISTS anomaly_baselines`); err != nil {
		t.Fatalf("drop table for cleanup: %v", err)
	}
}

func sampleSnapshot() anomalyusecase.IdentityStateSnapshot {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return anomalyusecase.IdentityStateSnapshot{
		Tools:       []string{"read_file"},
		WindowStart: now,
		Cur:         anomalyusecase.WindowCountsSnapshot{Total: 3, ToolCalls: 2},
		Prev:        anomalyusecase.WindowCountsSnapshot{Total: 5, ToolCalls: 4},
		LastSeen:    now,
		MLStats: anomalyusecase.MLFeatureStateSnapshot{
			Rate: anomalyusecase.OnlineStatSnapshot{Mean: 4.0, M2: 2.0, Count: 3},
		},
		LastCallAt: now,
	}
}

func TestPostgresBaselineStore_SaveThenLoadRoundTrips(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	snap := sampleSnapshot()
	key := "4:acme:alice"
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: snap}, nil); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	got, ok := loaded[key]
	if !ok {
		t.Fatalf("expected key %q in loaded map, got %v", key, loaded)
	}
	if got.Cur.Total != 3 || got.Prev.Total != 5 {
		t.Errorf("expected Cur.Total=3 Prev.Total=5, got Cur.Total=%d Prev.Total=%d", got.Cur.Total, got.Prev.Total)
	}
	if got.MLStats.Rate.Mean != 4.0 || got.MLStats.Rate.Count != 3 {
		t.Errorf("expected MLStats.Rate={Mean:4 Count:3}, got %+v", got.MLStats.Rate)
	}
	if len(got.Tools) != 1 || got.Tools[0] != "read_file" {
		t.Errorf("expected Tools=[read_file], got %v", got.Tools)
	}
}

func TestPostgresBaselineStore_SaveAllOverwritesExistingKey(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	key := "5:acme2:alice"
	first := sampleSnapshot()
	first.Cur.Total = 1
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: first}, nil); err != nil {
		t.Fatalf("first SaveAll: %v", err)
	}
	second := sampleSnapshot()
	second.Cur.Total = 99
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: second}, nil); err != nil {
		t.Fatalf("second SaveAll: %v", err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if loaded[key].Cur.Total != 99 {
		t.Errorf("expected the second SaveAll to overwrite, got Cur.Total=%d", loaded[key].Cur.Total)
	}
}

func TestPostgresBaselineStore_LoadAllSkipsCorruptRowsAndLogsWarn(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	s, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, logger)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	goodKey := "4:acme:bob"
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{goodKey: sampleSnapshot()}, nil); err != nil {
		t.Fatalf("SaveAll (good row): %v", err)
	}

	// Insert a corrupt row directly, bypassing SaveAll's own valid-JSON path.
	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer func() { _ = rawDB.Close() }()
	if _, err := rawDB.Exec(
		`INSERT INTO anomaly_baselines (instance_id, key, state, updated_at) VALUES ($1, $2, $3, now())`,
		testInstanceID, "corrupt-key", []byte(`{not valid json`),
	); err != nil {
		t.Fatalf("insert corrupt row: %v", err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll must not error on a corrupt row, got: %v", err)
	}
	if _, ok := loaded[goodKey]; !ok {
		t.Errorf("expected the good row to still load, got %v", loaded)
	}
	if _, ok := loaded["corrupt-key"]; ok {
		t.Error("expected the corrupt row to be skipped, not loaded")
	}
	if !strings.Contains(logBuf.String(), "corrupt-key") {
		t.Errorf("expected a Warn log naming the corrupt key, got log output: %q", logBuf.String())
	}
}

func TestPostgresBaselineStore_PruneStaleRemovesOnlyAbandonedRowsAcrossInstances(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	// Instance A (soon to be "abandoned") and instance B (still live), each
	// saving one row under its own instance ID.
	sA, err := adapter.NewPostgresBaselineStore(dsn, "instance-A", nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore A: %v", err)
	}
	defer func() { _ = sA.Close() }()
	sB, err := adapter.NewPostgresBaselineStore(dsn, "instance-B", nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore B: %v", err)
	}
	defer func() { _ = sB.Close() }()

	if err := sA.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{"4:acme:alice": sampleSnapshot()}, nil); err != nil {
		t.Fatalf("SaveAll A: %v", err)
	}
	if err := sB.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{"4:acme:bob": sampleSnapshot()}, nil); err != nil {
		t.Fatalf("SaveAll B: %v", err)
	}

	// Simulate instance A having stopped checkpointing: backdate its row's
	// updated_at to an hour ago. Instance B's row keeps its fresh timestamp.
	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer func() { _ = rawDB.Close() }()
	if _, err := rawDB.Exec(
		`UPDATE anomaly_baselines SET updated_at = now() - interval '1 hour' WHERE instance_id = $1`,
		"instance-A",
	); err != nil {
		t.Fatalf("backdate instance-A row: %v", err)
	}

	// Prune from instance B's store (cross-instance cleanup): rows older
	// than 10 minutes go, i.e. instance A's backdated row but not B's fresh one.
	n, err := sB.PruneStale(10 * time.Minute)
	if err != nil {
		t.Fatalf("PruneStale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 abandoned row pruned, got %d", n)
	}

	// Instance A's row is gone; instance B's survives.
	if loaded, err := sA.LoadAll(); err != nil {
		t.Fatalf("LoadAll A: %v", err)
	} else if len(loaded) != 0 {
		t.Errorf("expected instance A's abandoned rows pruned, got %v", loaded)
	}
	if loaded, err := sB.LoadAll(); err != nil {
		t.Fatalf("LoadAll B: %v", err)
	} else if _, ok := loaded["4:acme:bob"]; !ok {
		t.Errorf("expected instance B's fresh row to survive the prune, got %v", loaded)
	}

	// A second prune with nothing stale removes nothing (idempotent).
	if n, err := sB.PruneStale(10 * time.Minute); err != nil {
		t.Fatalf("second PruneStale: %v", err)
	} else if n != 0 {
		t.Errorf("expected 0 rows pruned on the second pass, got %d", n)
	}
}

func TestPostgresBaselineStore_LoadAllOnEmptyTableReturnsEmptyMap(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != 0 {
		t.Errorf("expected an empty map from an empty table, got %v", loaded)
	}
}

func TestPostgresBaselineStore_TableCreationIsIdempotent(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s1, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("first NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s1.Close() }()

	s2, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("second NewPostgresBaselineStore (should be idempotent): %v", err)
	}
	defer func() { _ = s2.Close() }()
}

func TestNewPostgresBaselineStore_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresBaselineStore("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable", testInstanceID, nil)
	if err == nil {
		t.Fatal("expected an error constructing a store against an unreachable database")
	}
}

// TestPostgresBaselineStore_CrossReplicaIsolation codifies I1's final-review
// finding: two replicas sharing one Postgres DSN must never clobber each
// other's checkpoint for the same (tenant, identity). Two stores with
// different instance IDs each save a different value for the exact same
// key, and each must reload only its own value back.
func TestPostgresBaselineStore_CrossReplicaIsolation(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s1, err := adapter.NewPostgresBaselineStore(dsn, "replica-1", nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore (replica-1): %v", err)
	}
	defer func() { _ = s1.Close() }()

	s2, err := adapter.NewPostgresBaselineStore(dsn, "replica-2", nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore (replica-2): %v", err)
	}
	defer func() { _ = s2.Close() }()

	key := "4:acme:alice"
	snap1 := sampleSnapshot()
	snap1.Cur.Total = 111
	snap2 := sampleSnapshot()
	snap2.Cur.Total = 222

	if err := s1.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: snap1}, nil); err != nil {
		t.Fatalf("replica-1 SaveAll: %v", err)
	}
	if err := s2.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: snap2}, nil); err != nil {
		t.Fatalf("replica-2 SaveAll: %v", err)
	}

	loaded1, err := s1.LoadAll()
	if err != nil {
		t.Fatalf("replica-1 LoadAll: %v", err)
	}
	loaded2, err := s2.LoadAll()
	if err != nil {
		t.Fatalf("replica-2 LoadAll: %v", err)
	}

	if got, ok := loaded1[key]; !ok || got.Cur.Total != 111 {
		t.Errorf("expected replica-1 to reload its own Cur.Total=111 for %q, got ok=%v got=%+v", key, ok, got)
	}
	if got, ok := loaded2[key]; !ok || got.Cur.Total != 222 {
		t.Errorf("expected replica-2 to reload its own Cur.Total=222 for %q, got ok=%v got=%+v", key, ok, got)
	}
}

// TestPostgresBaselineStore_SaveAllDeletesEvictedRows codifies I2's final
// review finding ("FINDING A CONFIRMED"): save two identities, evict one
// (as Detector's gc() would after a cutoff), confirm its Postgres row is
// gone via a fresh LoadAll while the other identity's row remains.
func TestPostgresBaselineStore_SaveAllDeletesEvictedRows(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	keepKey := "4:acme:alice"
	evictKey := "4:acme:bob"
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{
		keepKey:  sampleSnapshot(),
		evictKey: sampleSnapshot(),
	}, nil); err != nil {
		t.Fatalf("initial SaveAll: %v", err)
	}

	// Simulate the next GC tick: evictKey has aged out of d.state, so it's
	// no longer in snapshots, and is instead passed as a deletedKey.
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{
		keepKey: sampleSnapshot(),
	}, []string{evictKey}); err != nil {
		t.Fatalf("SaveAll with deletedKeys: %v", err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, ok := loaded[evictKey]; ok {
		t.Errorf("expected the evicted identity's row to be deleted, but it reloaded: %v", loaded[evictKey])
	}
	if _, ok := loaded[keepKey]; !ok {
		t.Errorf("expected the surviving identity's row to remain, got %v", loaded)
	}
}

// TestPostgresBaselineStore_SaveAllBatchesLargeMaps codifies I3's final
// review finding: SaveAll must not hit a single unchunked transaction's
// deadline at scale. 1200 keys is comfortably past one
// baselineSaveBatchSize-sized batch (3 batches at 500/batch), so this
// exercises the multi-batch path; a correctness round-trip is the
// right-sized regression here, not a reproduction of the reviewer's
// 34k/50k-row timing numbers (slow, environment-sensitive, and not what
// this test needs to prove).
func TestPostgresBaselineStore_SaveAllBatchesLargeMaps(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s, err := adapter.NewPostgresBaselineStore(dsn, testInstanceID, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	const n = 1200
	snapshots := make(map[string]anomalyusecase.IdentityStateSnapshot, n)
	for i := 0; i < n; i++ {
		snap := sampleSnapshot()
		snap.Cur.Total = i
		snapshots[fmt.Sprintf("4:acme:user-%d", i)] = snap
	}

	if err := s.SaveAll(snapshots, nil); err != nil {
		t.Fatalf("SaveAll of %d keys: %v", n, err)
	}

	loaded, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(loaded) != n {
		t.Fatalf("expected all %d keys to round-trip, got %d", n, len(loaded))
	}
	for key, want := range snapshots {
		got, ok := loaded[key]
		if !ok {
			t.Fatalf("expected key %q in loaded map", key)
		}
		if got.Cur.Total != want.Cur.Total {
			t.Errorf("key %q: expected Cur.Total=%d, got %d", key, want.Cur.Total, got.Cur.Total)
		}
	}
}
