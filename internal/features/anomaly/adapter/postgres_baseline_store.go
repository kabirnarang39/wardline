package adapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

// baselineStoreTimeout bounds every Postgres operation this adapter
// performs -- same rationale and value as credential/adapter.revokerTimeout
// and budget/adapter.budgetLimiterTimeout. LoadAll/SaveAll run at
// startup and on the GC ticker (never on the request path -- see this
// plan's Global Constraints), but a blackholed connection must still
// degrade to a bounded error rather than hang the ticker goroutine or
// startup forever.
const baselineStoreTimeout = 5 * time.Second

// state is TEXT, not JSONB: a JSONB column rejects invalid JSON at INSERT
// time (SQLSTATE 22P02), which would make row-level corruption
// impossible to reach in the first place -- verified locally, the
// corrupt-row INSERT in this adapter's own test fails at the database
// with a JSONB column. TEXT stores whatever bytes SaveAll's
// json.Marshal produced (always valid JSON on the write path) while
// still letting a row corrupted by any other means (manual edit, a
// future migration bug, disk-level corruption) round-trip through
// LoadAll's per-row json.Unmarshal and get skipped-with-Warn instead of
// being rejected by Postgres before this adapter ever sees it.
const createBaselinesTableSQL = `
CREATE TABLE IF NOT EXISTS anomaly_baselines (
	key TEXT PRIMARY KEY,
	state TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
)`

const upsertBaselineSQL = `
INSERT INTO anomaly_baselines (key, state, updated_at)
VALUES ($1, $2, $3)
ON CONFLICT (key) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at`

const selectAllBaselinesSQL = `SELECT key, state FROM anomaly_baselines`

// PostgresBaselineStore persists Detector's per-identity baselines
// (internal/features/anomaly/usecase.IdentityStateSnapshot) to a shared
// Postgres database -- the persistence half of this plan. key is the
// exact tenantIdentityKey(tenant, identity) string
// internal/features/anomaly/usecase.Detector.state is itself keyed by
// (see tenant_key.go) -- LoadAll/SaveAll never decode or re-derive
// tenant/identity from it, sidestepping the key-encoding/decoding bug
// class a prior cycle's Postgres refresh-token store had to fix.
type PostgresBaselineStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresBaselineStore opens a connection pool to dsn, creates the
// anomaly_baselines table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first LoadAll/SaveAll call. logger is
// used to surface a corrupt row skipped by LoadAll -- may be nil (see
// LoadAll).
func NewPostgresBaselineStore(dsn string, logger *slog.Logger) (*PostgresBaselineStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createBaselinesTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create anomaly_baselines table: %w", err)
	}

	return &PostgresBaselineStore{db: db, logger: logger}, nil
}

// LoadAll returns every persisted baseline, keyed by the same
// tenantIdentityKey string they were saved under. A single row whose
// state column fails to json.Unmarshal is skipped (logged at Warn if a
// logger was supplied) rather than failing the whole call -- see this
// plan's Global Constraints on per-key fail-closed behavior. An empty
// table returns a non-nil, empty map and a nil error.
func (s *PostgresBaselineStore) LoadAll() (map[string]anomalyusecase.IdentityStateSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, selectAllBaselinesSQL)
	if err != nil {
		return nil, fmt.Errorf("query anomaly_baselines: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]anomalyusecase.IdentityStateSnapshot)
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, fmt.Errorf("scan anomaly_baselines row: %w", err)
		}
		var snap anomalyusecase.IdentityStateSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			if s.logger != nil {
				s.logger.Warn("skipping corrupt anomaly baseline row: identity will re-learn as novel", "key", key, "error", err)
			}
			continue
		}
		out[key] = snap
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate anomaly_baselines rows: %w", err)
	}
	return out, nil
}

// SaveAll upserts every provided snapshot in one transaction. Called
// from Detector's GC tick (internal/features/anomaly/usecase/gc.go),
// never on the request path.
func (s *PostgresBaselineStore) SaveAll(snapshots map[string]anomalyusecase.IdentityStateSnapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	now := time.Now()
	for key, snap := range snapshots {
		raw, err := json.Marshal(snap)
		if err != nil {
			return fmt.Errorf("marshal snapshot for key %q: %w", key, err)
		}
		if _, err := tx.ExecContext(ctx, upsertBaselineSQL, key, raw, now); err != nil {
			return fmt.Errorf("upsert baseline for key %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit baseline save: %w", err)
	}
	return nil
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (s *PostgresBaselineStore) Close() error {
	return s.db.Close()
}
