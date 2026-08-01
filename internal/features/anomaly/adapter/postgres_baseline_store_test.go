package adapter_test

import (
	"bytes"
	"database/sql"
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

	s, err := adapter.NewPostgresBaselineStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	snap := sampleSnapshot()
	key := "4:acme:alice"
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: snap}); err != nil {
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

	s, err := adapter.NewPostgresBaselineStore(dsn, nil)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	key := "5:acme2:alice"
	first := sampleSnapshot()
	first.Cur.Total = 1
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: first}); err != nil {
		t.Fatalf("first SaveAll: %v", err)
	}
	second := sampleSnapshot()
	second.Cur.Total = 99
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{key: second}); err != nil {
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

	s, err := adapter.NewPostgresBaselineStore(dsn, logger)
	if err != nil {
		t.Fatalf("NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	goodKey := "4:acme:bob"
	if err := s.SaveAll(map[string]anomalyusecase.IdentityStateSnapshot{goodKey: sampleSnapshot()}); err != nil {
		t.Fatalf("SaveAll (good row): %v", err)
	}

	// Insert a corrupt row directly, bypassing SaveAll's own valid-JSON path.
	rawDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer func() { _ = rawDB.Close() }()
	if _, err := rawDB.Exec(
		`INSERT INTO anomaly_baselines (key, state, updated_at) VALUES ($1, $2, now())`,
		"corrupt-key", []byte(`{not valid json`),
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

func TestPostgresBaselineStore_LoadAllOnEmptyTableReturnsEmptyMap(t *testing.T) {
	dsn := baselineTestDSN(t)
	dropBaselinesTable(t, dsn)

	s, err := adapter.NewPostgresBaselineStore(dsn, nil)
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

	s1, err := adapter.NewPostgresBaselineStore(dsn, nil)
	if err != nil {
		t.Fatalf("first NewPostgresBaselineStore: %v", err)
	}
	defer func() { _ = s1.Close() }()

	s2, err := adapter.NewPostgresBaselineStore(dsn, nil)
	if err != nil {
		t.Fatalf("second NewPostgresBaselineStore (should be idempotent): %v", err)
	}
	defer func() { _ = s2.Close() }()
}

func TestNewPostgresBaselineStore_BadDSNFailsFast(t *testing.T) {
	_, err := adapter.NewPostgresBaselineStore("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable", nil)
	if err == nil {
		t.Fatal("expected an error constructing a store against an unreachable database")
	}
}
