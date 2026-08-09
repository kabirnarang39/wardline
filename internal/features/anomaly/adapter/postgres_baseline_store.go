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
// startup forever. SaveAll further chunks its work into batches (see
// baselineSaveBatchSize) so this deadline bounds one batch, not an
// arbitrarily large map in one shot.
const baselineStoreTimeout = 5 * time.Second

// baselineSaveBatchSize bounds how many upserts/deletes share one
// transaction/timeout in SaveAll. Without this, one BeginTx/Commit
// covering the whole map means baselineStoreTimeout has to cover every
// sequential per-key ExecContext -- past roughly 34k identities over
// loopback this blew the 5s deadline outright, and because SaveAll's
// failure is all-or-nothing, every following GC tick failed identically
// and persistence silently stopped for good. Chunking means an
// arbitrarily large map still completes -- just proportionally slower
// across the GC interval -- instead of failing past a size cliff.
const baselineSaveBatchSize = 500

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
//
// Keyed on (instance_id, key), not key alone: two replicas sharing one
// Postgres DSN (the documented HA config) each get their own row per
// (tenant, identity) instead of last-writer-wins clobbering each
// other's checkpoint -- instance_id defaults to os.Hostname() (see
// cmd/wardline/main.go's deriveInstanceID), so a replica's rows survive
// its own restarts but become orphaned (never read, never cleaned up --
// see docs' Known Limitations) if its hostname ever changes, e.g. pod
// recreation on a rolling deploy.
const createBaselinesTableSQL = `
CREATE TABLE IF NOT EXISTS anomaly_baselines (
	instance_id TEXT NOT NULL,
	key TEXT NOT NULL,
	state TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (instance_id, key)
)`

const upsertBaselineSQL = `
INSERT INTO anomaly_baselines (instance_id, key, state, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (instance_id, key) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at`

const deleteBaselinesSQL = `DELETE FROM anomaly_baselines WHERE instance_id = $1 AND key = ANY($2)`

const selectAllBaselinesSQL = `SELECT key, state FROM anomaly_baselines WHERE instance_id = $1`

// createBaselinesUpdatedAtIndexSQL indexes updated_at so PruneStale's
// range delete is an index scan rather than a full table scan -- the
// table can hold one row per (instance, tenant, identity) across a whole
// fleet, and every live replica runs PruneStale on its own GC tick.
const createBaselinesUpdatedAtIndexSQL = `CREATE INDEX IF NOT EXISTS anomaly_baselines_updated_at_idx ON anomaly_baselines (updated_at)`

// pruneStaleBaselinesSQL deletes every row -- across all instance IDs, not
// just this store's own -- whose updated_at is older than the cutoff. A
// live replica re-upserts every one of its in-memory identities' rows on
// each GC tick (see usecase/gc.go), advancing their updated_at, so only
// rows belonging to an instance that has stopped checkpointing entirely (a
// scaled-down replica, or one whose hostname changed and orphaned its old
// rows) ever fall past a cutoff set safely beyond one GC interval.
const pruneStaleBaselinesSQL = `DELETE FROM anomaly_baselines WHERE updated_at < $1`

// PostgresBaselineStore persists Detector's per-identity baselines
// (internal/features/anomaly/usecase.IdentityStateSnapshot) to a shared
// Postgres database -- the persistence half of this plan. key is the
// exact tenantIdentityKey(tenant, identity) string
// internal/features/anomaly/usecase.Detector.state is itself keyed by
// (see tenant_key.go) -- LoadAll/SaveAll never decode or re-derive
// tenant/identity from it, sidestepping the key-encoding/decoding bug
// class a prior cycle's Postgres refresh-token store had to fix.
//
// instanceID is fixed for this store's whole process lifetime (one
// store instance = one instance ID) -- LoadAll only ever reloads this
// instance's own rows, and SaveAll only ever writes/deletes this
// instance's own rows, so two replicas sharing one DSN never see or
// clobber each other's baselines.
type PostgresBaselineStore struct {
	db         *sql.DB
	logger     *slog.Logger
	instanceID string
}

// NewPostgresBaselineStore opens a connection pool to dsn, creates the
// anomaly_baselines table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first LoadAll/SaveAll call. logger is
// used to surface a corrupt row skipped by LoadAll -- may be nil (see
// LoadAll). instanceID identifies this replica (see
// cmd/wardline/main.go's deriveInstanceID) and scopes every row this
// store reads or writes -- callers must pass the same stable value
// across a process's whole lifetime.
func NewPostgresBaselineStore(dsn string, instanceID string, logger *slog.Logger) (*PostgresBaselineStore, error) {
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
	if _, err := db.ExecContext(createCtx, createBaselinesUpdatedAtIndexSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create anomaly_baselines updated_at index: %w", err)
	}

	return &PostgresBaselineStore{db: db, logger: logger, instanceID: instanceID}, nil
}

// LoadAll returns every persisted baseline belonging to this store's own
// instanceID, keyed by the same tenantIdentityKey string they were saved
// under -- a replica never reloads another replica's rows. A single row
// whose state column fails to json.Unmarshal is skipped (logged at Warn
// if a logger was supplied) rather than failing the whole call -- see
// this plan's Global Constraints on per-key fail-closed behavior. An
// empty table (or no rows for this instance ID) returns a non-nil, empty
// map and a nil error.
func (s *PostgresBaselineStore) LoadAll() (map[string]anomalyusecase.IdentityStateSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, selectAllBaselinesSQL, s.instanceID)
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

// SaveAll upserts every provided snapshot and deletes every row named in
// deletedKeys (the identities GC just evicted from memory -- see this
// plan's gc.go -- so an evicted identity's row doesn't survive in
// Postgres and resurrect a stale baseline on the next restart). Called
// from Detector's GC tick (internal/features/anomaly/usecase/gc.go),
// never on the request path.
//
// Both the upserts and the deletes are chunked into batches of
// baselineSaveBatchSize keys, each batch its own transaction with its
// own fresh baselineStoreTimeout deadline -- one unchunked transaction
// covering an arbitrarily large map hit its deadline outright past
// roughly 34k identities, failing the whole checkpoint (and every
// following one identically). Batching means a large map still
// completes, just proportionally slower. If a batch fails, SaveAll
// aborts immediately and returns that error -- matching the previous
// all-or-nothing-per-call semantics, just at batch granularity instead
// of unbounded.
//
// A nil/empty snapshots with a non-empty deletedKeys (or vice versa)
// still runs its non-empty half; only both-empty short-circuits.
func (s *PostgresBaselineStore) SaveAll(snapshots map[string]anomalyusecase.IdentityStateSnapshot, deletedKeys []string) error {
	if len(snapshots) == 0 && len(deletedKeys) == 0 {
		return nil
	}

	// Deletes run before upserts: deletedKeys is a one-shot list built
	// fresh each GC tick from that tick's own evictions (gc.go) -- if an
	// upsert batch fails and SaveAll returns early, there is no later
	// retry of this tick's deletes, so leaving them for last would let a
	// transient upsert failure permanently orphan rows that should have
	// been removed (silently reintroducing the evicted-row-resurrection
	// bug this delete path exists to prevent). Running deletes first
	// makes deletion the durable half regardless of what happens to the
	// upserts that follow.
	for i := 0; i < len(deletedKeys); i += baselineSaveBatchSize {
		end := i + baselineSaveBatchSize
		if end > len(deletedKeys) {
			end = len(deletedKeys)
		}
		if err := s.deleteBatch(deletedKeys[i:end]); err != nil {
			return err
		}
	}

	keys := make([]string, 0, len(snapshots))
	for key := range snapshots {
		keys = append(keys, key)
	}
	for i := 0; i < len(keys); i += baselineSaveBatchSize {
		end := i + baselineSaveBatchSize
		if end > len(keys) {
			end = len(keys)
		}
		if err := s.saveBatch(keys[i:end], snapshots); err != nil {
			return err
		}
	}
	return nil
}

// saveBatch upserts exactly the snapshots named by batchKeys, in its own
// transaction with its own fresh baselineStoreTimeout deadline.
func (s *PostgresBaselineStore) saveBatch(batchKeys []string, snapshots map[string]anomalyusecase.IdentityStateSnapshot) error {
	ctx, cancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	now := time.Now()
	for _, key := range batchKeys {
		raw, err := json.Marshal(snapshots[key])
		if err != nil {
			return fmt.Errorf("marshal snapshot for key %q: %w", key, err)
		}
		if _, err := tx.ExecContext(ctx, upsertBaselineSQL, s.instanceID, key, raw, now); err != nil {
			return fmt.Errorf("upsert baseline for key %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit baseline save: %w", err)
	}
	return nil
}

// deleteBatch removes exactly the rows named by batchKeys (scoped to
// this store's own instanceID), in its own transaction with its own
// fresh baselineStoreTimeout deadline.
func (s *PostgresBaselineStore) deleteBatch(batchKeys []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	if _, err := tx.ExecContext(ctx, deleteBaselinesSQL, s.instanceID, batchKeys); err != nil {
		return fmt.Errorf("delete evicted baselines: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit baseline delete: %w", err)
	}
	return nil
}

// PruneStale deletes every baseline row -- across all instance IDs -- whose
// updated_at is older than olderThan before now, returning how many rows
// were removed. It exists to clean up rows left behind by an instance that
// has stopped checkpointing entirely (a permanently scaled-down replica, or
// one whose hostname changed and orphaned its old rows): SaveAll's
// per-eviction delete only removes rows for identities a still-running
// instance evicts, never a whole abandoned instance's set. Callers must
// pass an olderThan comfortably larger than the GC interval so a live
// replica's own rows -- re-upserted every tick -- are never caught (see
// usecase/gc.go's prune wiring). Safe to run from every replica each tick:
// the delete is idempotent, and rows already removed by another replica's
// prune simply match nothing.
func (s *PostgresBaselineStore) PruneStale(olderThan time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), baselineStoreTimeout)
	defer cancel()

	res, err := s.db.ExecContext(ctx, pruneStaleBaselinesSQL, time.Now().Add(-olderThan))
	if err != nil {
		return 0, fmt.Errorf("prune stale baselines: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count pruned baselines: %w", err)
	}
	return n, nil
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (s *PostgresBaselineStore) Close() error {
	return s.db.Close()
}
