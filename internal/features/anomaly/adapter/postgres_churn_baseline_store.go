package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
)

const churnBaselineStoreTimeout = 5 * time.Second

// identity_churn_baselines is a distinct table from tenant_baselines,
// not a reuse of it: it carries an extra cusum column tenant_anomaly
// has no use for (tenant_anomaly has no CUSUM extension) -- see
// usecase.ChurnBaselineSnapshot's own doc comment for why the two types
// (and therefore the two tables) are kept separate rather than forcing
// a dead, always-zero column onto every tenant_anomaly row.
const createChurnBaselinesTableSQL = `
CREATE TABLE IF NOT EXISTS identity_churn_baselines (
	instance_id TEXT NOT NULL,
	tenant      TEXT NOT NULL,
	mean        DOUBLE PRECISION NOT NULL,
	m2          DOUBLE PRECISION NOT NULL,
	count       BIGINT NOT NULL,
	cusum       DOUBLE PRECISION NOT NULL DEFAULT 0,
	updated_at  TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (instance_id, tenant)
)`

const upsertChurnBaselineSQL = `
INSERT INTO identity_churn_baselines (instance_id, tenant, mean, m2, count, cusum, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (instance_id, tenant) DO UPDATE SET
	mean = EXCLUDED.mean, m2 = EXCLUDED.m2, count = EXCLUDED.count, cusum = EXCLUDED.cusum, updated_at = EXCLUDED.updated_at`

const selectAllChurnBaselinesSQL = `SELECT tenant, mean, m2, count, cusum FROM identity_churn_baselines WHERE instance_id = $1`

// PostgresChurnBaselineStore persists identity_churn's per-tenant
// running baseline AND CUSUM accumulator for restart-survival, keyed by
// (instance_id, tenant) -- the identity_churn sibling of
// PostgresTenantBaselineStore, deliberately NOT shared across replicas
// the way PostgresChurnWindowStore's rows are (see checkIdentityChurn's
// own doc comment on the "fold the merged total" correctness property):
// every replica converges to the same baseline and CUSUM value by
// folding the same cross-replica-merged window total through the exact
// same deterministic arithmetic (Welford's algorithm for the baseline,
// cusumStep for the accumulator), not by reading each other's rows.
type PostgresChurnBaselineStore struct {
	db         *sql.DB
	instanceID string
	logger     *slog.Logger
}

// NewPostgresChurnBaselineStore creates identity_churn_baselines on db
// if it doesn't already exist. db is expected already open and pinged
// (see pgpool.Open, called once in cmd/wardline/main.go and shared
// across every Postgres-backed feature) -- a bad db fails here, at
// construction time.
func NewPostgresChurnBaselineStore(db *sql.DB, instanceID string, logger *slog.Logger) (*PostgresChurnBaselineStore, error) {
	createCtx, createCancel := context.WithTimeout(context.Background(), churnBaselineStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createChurnBaselinesTableSQL); err != nil {
		return nil, fmt.Errorf("create identity_churn_baselines table: %w", err)
	}

	return &PostgresChurnBaselineStore{db: db, instanceID: instanceID, logger: logger}, nil
}

// LoadAll returns this instance's own previously-checkpointed
// identity_churn baselines -- called once at startup, mirroring
// PostgresTenantBaselineStore.LoadAll's own timing (never on the
// request path).
func (s *PostgresChurnBaselineStore) LoadAll() (map[string]anomalyusecase.ChurnBaselineSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), churnBaselineStoreTimeout)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, selectAllChurnBaselinesSQL, s.instanceID)
	if err != nil {
		return nil, fmt.Errorf("select identity_churn baselines: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]anomalyusecase.ChurnBaselineSnapshot)
	for rows.Next() {
		var tenant string
		var snap anomalyusecase.ChurnBaselineSnapshot
		if err := rows.Scan(&tenant, &snap.Mean, &snap.M2, &snap.Count, &snap.CUSUM); err != nil {
			return nil, fmt.Errorf("scan identity_churn baseline row: %w", err)
		}
		out[tenant] = snap
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity_churn baseline rows: %w", err)
	}
	return out, nil
}

// SaveAll upserts every given tenant's current baseline and CUSUM
// accumulator under this instance's own ID -- called on the same GC
// tick identityState's own checkpoint already runs on (see gc.go),
// never on the request path. Tenant cardinality is orders of magnitude
// below identity cardinality in any real deployment, so (unlike
// PostgresBaselineStore.SaveAll) this doesn't need batching -- one
// transaction covers every tenant.
func (s *PostgresChurnBaselineStore) SaveAll(baselines map[string]anomalyusecase.ChurnBaselineSnapshot) error {
	if len(baselines) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), churnBaselineStoreTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin identity_churn baseline save transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	for tenant, snap := range baselines {
		if _, err := tx.ExecContext(ctx, upsertChurnBaselineSQL, s.instanceID, tenant, snap.Mean, snap.M2, snap.Count, snap.CUSUM, now); err != nil {
			return fmt.Errorf("upsert identity_churn baseline for %q: %w", tenant, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit identity_churn baseline save transaction: %w", err)
	}
	return nil
}
