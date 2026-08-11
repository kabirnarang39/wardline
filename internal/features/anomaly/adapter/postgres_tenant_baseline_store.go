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

const tenantBaselineStoreTimeout = 5 * time.Second

const createTenantBaselinesTableSQL = `
CREATE TABLE IF NOT EXISTS tenant_baselines (
	instance_id TEXT NOT NULL,
	tenant      TEXT NOT NULL,
	mean        DOUBLE PRECISION NOT NULL,
	m2          DOUBLE PRECISION NOT NULL,
	count       BIGINT NOT NULL,
	updated_at  TIMESTAMPTZ NOT NULL,
	PRIMARY KEY (instance_id, tenant)
)`

const upsertTenantBaselineSQL = `
INSERT INTO tenant_baselines (instance_id, tenant, mean, m2, count, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (instance_id, tenant) DO UPDATE SET
	mean = EXCLUDED.mean, m2 = EXCLUDED.m2, count = EXCLUDED.count, updated_at = EXCLUDED.updated_at`

const selectAllTenantBaselinesSQL = `SELECT tenant, mean, m2, count FROM tenant_baselines WHERE instance_id = $1`

// PostgresTenantBaselineStore persists tenant_anomaly's per-tenant
// running baseline (mean/m2/count -- onlineStat's whole state) for
// restart-survival, keyed by (instance_id, tenant) -- deliberately NOT
// shared across replicas the way PostgresTenantWindowStore's rows are
// (see checkTenantDrift's own doc comment on the "key correctness
// property"): every replica converges to the same baseline by folding
// the same cross-replica-merged window total, not by reading each
// other's baseline rows. instance_id is the same hostname-based
// derivation identityState's own PostgresBaselineStore already uses.
//
// Plain numeric columns, not JSON like PostgresBaselineStore's `state`
// column: onlineStat has no nested structure (three flat numbers), so
// there's nothing serialization would buy here.
type PostgresTenantBaselineStore struct {
	db         *sql.DB
	instanceID string
	logger     *slog.Logger
}

// NewPostgresTenantBaselineStore opens a connection pool to dsn,
// creates tenant_baselines if it doesn't exist, and pings the
// connection -- a bad DSN fails here, at construction, matching every
// other Postgres-backed adapter's own precedent.
func NewPostgresTenantBaselineStore(dsn, instanceID string, logger *slog.Logger) (*PostgresTenantBaselineStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), tenantBaselineStoreTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), tenantBaselineStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createTenantBaselinesTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create tenant_baselines table: %w", err)
	}

	return &PostgresTenantBaselineStore{db: db, instanceID: instanceID, logger: logger}, nil
}

// LoadAll returns this instance's own previously-checkpointed tenant
// baselines -- called once at startup, mirroring
// PostgresBaselineStore.LoadAll's own timing (never on the request
// path).
func (s *PostgresTenantBaselineStore) LoadAll() (map[string]anomalyusecase.OnlineStatSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tenantBaselineStoreTimeout)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, selectAllTenantBaselinesSQL, s.instanceID)
	if err != nil {
		return nil, fmt.Errorf("select tenant baselines: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]anomalyusecase.OnlineStatSnapshot)
	for rows.Next() {
		var tenant string
		var snap anomalyusecase.OnlineStatSnapshot
		if err := rows.Scan(&tenant, &snap.Mean, &snap.M2, &snap.Count); err != nil {
			return nil, fmt.Errorf("scan tenant baseline row: %w", err)
		}
		out[tenant] = snap
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant baseline rows: %w", err)
	}
	return out, nil
}

// SaveAll upserts every given tenant's current baseline under this
// instance's own ID -- called on the same GC tick identityState's own
// checkpoint already runs on (see gc.go), never on the request path.
// Tenant cardinality is orders of magnitude below identity cardinality
// in any real deployment, so (unlike PostgresBaselineStore.SaveAll)
// this doesn't need batching -- one transaction covers every tenant.
func (s *PostgresTenantBaselineStore) SaveAll(baselines map[string]anomalyusecase.OnlineStatSnapshot) error {
	if len(baselines) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), tenantBaselineStoreTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tenant baseline save transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	for tenant, snap := range baselines {
		if _, err := tx.ExecContext(ctx, upsertTenantBaselineSQL, s.instanceID, tenant, snap.Mean, snap.M2, snap.Count, now); err != nil {
			return fmt.Errorf("upsert tenant baseline for %q: %w", tenant, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tenant baseline save transaction: %w", err)
	}
	return nil
}

// Close releases the underlying connection pool.
func (s *PostgresTenantBaselineStore) Close() error {
	return s.db.Close()
}
