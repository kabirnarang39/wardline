package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// tenantWindowStoreTimeout matches every other Postgres-backed
// adapter's established bound (budgetLimiterTimeout, revokerTimeout,
// baselineStoreTimeout) -- this sits on checkTenantDrift's own call
// path (once per window, not per proxied call, but still must not hang
// indefinitely on a blackholed connection).
const tenantWindowStoreTimeout = 5 * time.Second

const createTenantWindowTotalsTableSQL = `
CREATE TABLE IF NOT EXISTS tenant_window_totals (
	tenant       TEXT NOT NULL,
	window_start TIMESTAMPTZ NOT NULL,
	total        INTEGER NOT NULL,
	PRIMARY KEY (tenant, window_start)
)`

// addAndGetSQL is a pure additive merge -- no conditional/decision
// logic (unlike budget's checkAndAdvance), because there is no
// allow/deny to compute here, only a running sum every replica
// contributes its own window's local delta into. Postgres's row-level
// locking on the conflicting (tenant, window_start) key serializes
// concurrent contributions from different replicas correctly, the same
// guarantee checkAndAdvance's own upsert already relies on for a
// harder (decision, not just sum) problem.
const addAndGetSQL = `
INSERT INTO tenant_window_totals (tenant, window_start, total)
VALUES ($1, $2, $3)
ON CONFLICT (tenant, window_start) DO UPDATE SET
	total = tenant_window_totals.total + $3
RETURNING total`

// PostgresTenantWindowStore is tenant_anomaly's genuinely-cross-replica
// half of its HA story -- see PostgresTenantBaselineStore for the other
// half, which is deliberately NOT cross-replica-merged the same way
// (see that type's own doc comment). Every replica connects to the
// same DSN, so a tenant's window total reflects every replica's
// contribution, not just this one's.
type PostgresTenantWindowStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresTenantWindowStore creates tenant_window_totals on db if it
// doesn't already exist. db is expected already open and pinged (see
// pgpool.Open, called once in cmd/wardline/main.go and shared across
// every Postgres-backed feature) -- a bad db fails here, at construction
// time, not on the first AddAndGet call, matching every other
// Postgres-backed adapter's own precedent.
func NewPostgresTenantWindowStore(db *sql.DB, logger *slog.Logger) (*PostgresTenantWindowStore, error) {
	createCtx, createCancel := context.WithTimeout(context.Background(), tenantWindowStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createTenantWindowTotalsTableSQL); err != nil {
		return nil, fmt.Errorf("create tenant_window_totals table: %w", err)
	}

	return &PostgresTenantWindowStore{db: db, logger: logger}, nil
}

// AddAndGet atomically adds delta (this replica's own just-finished
// window's local total) into the shared row for (tenantName,
// windowStart) and returns the resulting cross-replica merged total --
// one round trip, no read-then-write race window.
func (s *PostgresTenantWindowStore) AddAndGet(tenantName string, windowStart time.Time, delta int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tenantWindowStoreTimeout)
	defer cancel()

	var total int
	err := s.db.QueryRowContext(ctx, addAndGetSQL, tenantName, windowStart, delta).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("add and get tenant window total: %w", err)
	}
	return total, nil
}
