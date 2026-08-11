package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// churnWindowStoreTimeout matches every other Postgres-backed adapter's
// established bound (tenantWindowStoreTimeout, revokerTimeout,
// baselineStoreTimeout).
const churnWindowStoreTimeout = 5 * time.Second

// identity_churn_window_totals is a distinct table from
// tenant_window_totals, not a reuse of it: churn counts and
// tenant_anomaly's call-volume totals are different metrics that must
// never collide in the same (tenant, window_start) row -- neither table
// has a metric-kind discriminator column, so sharing one would silently
// sum two unrelated signals together.
const createChurnWindowTotalsTableSQL = `
CREATE TABLE IF NOT EXISTS identity_churn_window_totals (
	tenant       TEXT NOT NULL,
	window_start TIMESTAMPTZ NOT NULL,
	total        INTEGER NOT NULL,
	PRIMARY KEY (tenant, window_start)
)`

// addAndGetChurnSQL mirrors tenant_window_totals' own addAndGetSQL
// exactly -- pure additive merge, Postgres's row-level locking on the
// conflicting key serializes concurrent replica contributions.
const addAndGetChurnSQL = `
INSERT INTO identity_churn_window_totals (tenant, window_start, total)
VALUES ($1, $2, $3)
ON CONFLICT (tenant, window_start) DO UPDATE SET
	total = identity_churn_window_totals.total + $3
RETURNING total`

// PostgresChurnWindowStore is identity_churn's genuinely-cross-replica
// half of its HA story -- the identity_churn sibling of
// PostgresTenantWindowStore, same mechanics, separate table (see this
// file's own doc comment on why sharing one table would be wrong).
type PostgresChurnWindowStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresChurnWindowStore creates identity_churn_window_totals on db
// if it doesn't already exist. db is expected already open and pinged
// (see pgpool.Open, called once in cmd/wardline/main.go and shared
// across every Postgres-backed feature) -- a bad db fails here, at
// construction time, not on the first AddAndGet call.
func NewPostgresChurnWindowStore(db *sql.DB, logger *slog.Logger) (*PostgresChurnWindowStore, error) {
	createCtx, createCancel := context.WithTimeout(context.Background(), churnWindowStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createChurnWindowTotalsTableSQL); err != nil {
		return nil, fmt.Errorf("create identity_churn_window_totals table: %w", err)
	}

	return &PostgresChurnWindowStore{db: db, logger: logger}, nil
}

// AddAndGet atomically adds delta (this replica's own just-finished
// window's local new-identity count) into the shared row for
// (tenantName, windowStart) and returns the resulting cross-replica
// merged total -- one round trip, no read-then-write race window.
func (s *PostgresChurnWindowStore) AddAndGet(tenantName string, windowStart time.Time, delta int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), churnWindowStoreTimeout)
	defer cancel()

	var total int
	err := s.db.QueryRowContext(ctx, addAndGetChurnSQL, tenantName, windowStart, delta).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("add and get identity_churn window total: %w", err)
	}
	return total, nil
}
