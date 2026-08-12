package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
)

// costBudgetMeterTimeout bounds every Postgres operation this adapter
// performs -- same rationale as jobbudget.PostgresMeter's own timeout: Add
// sits on the request path when cost_budget is on, so a blackholed
// connection must degrade to a bounded error (the Checker then fails
// open), not hang the caller.
const costBudgetMeterTimeout = 5 * time.Second

const createCostBudgetTableSQL = `
CREATE TABLE IF NOT EXISTS cost_budget_counters (
	key TEXT PRIMARY KEY,
	total INTEGER NOT NULL
)`

// addSQL is the atomic upsert-and-add this adapter depends on: one
// INSERT ... ON CONFLICT DO UPDATE ... RETURNING round trip, no separate
// read-then-write -- concurrent callers for the same key serialize on the
// row lock and each see a distinct, correctly summed total. Simpler than
// jobbudget.PostgresMeter's incrementSQL: parameterized by amount instead
// of a hardcoded +1, and simpler than budget.PostgresLimiter's version:
// there is no window to expire and reset here, so there is no CASE-based
// expiry branch to encode.
const addSQL = `
INSERT INTO cost_budget_counters (key, total)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET total = cost_budget_counters.total + $2
RETURNING total`

// currentSQL reads without writing -- no INSERT, no ON CONFLICT. A
// never-seen key means sql.ErrNoRows, which Current below turns into
// (0, nil), matching InMemoryMeter's zero-value-for-absent-key behavior.
const currentSQL = `SELECT total FROM cost_budget_counters WHERE key = $1`

// listNearCeilingSQL backs ListNearCeiling -- the dashboard-only,
// optional Lister capability (see domain.Lister's doc comment). Ordered
// by total descending so the callers nearest their ceiling sort first.
const listNearCeilingSQL = `SELECT key, total FROM cost_budget_counters ORDER BY total DESC LIMIT $1`

// PostgresMeter satisfies domain.Meter, sharing running totals across
// every Wardline replica pointed at the same DSN -- required for
// cost_budget to mean anything behind a load balancer, the same reason
// jobbudget.PostgresMeter and budget.PostgresLimiter exist.
type PostgresMeter struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresMeter creates the cost_budget_counters table on db if it
// doesn't already exist. db is expected already open and pinged (see
// pgpool.Open, called once in cmd/wardline/main.go and shared across
// every Postgres-backed feature) -- a bad db fails here, at construction
// time, not on the first Add call.
func NewPostgresMeter(db *sql.DB, logger *slog.Logger) (*PostgresMeter, error) {
	ctx, cancel := context.WithTimeout(context.Background(), costBudgetMeterTimeout)
	defer cancel()
	if _, err := db.ExecContext(ctx, createCostBudgetTableSQL); err != nil {
		return nil, fmt.Errorf("create cost_budget_counters table: %w", err)
	}
	return &PostgresMeter{db: db, logger: logger}, nil
}

var _ domain.Meter = (*PostgresMeter)(nil)
var _ domain.Lister = (*PostgresMeter)(nil)

func (m *PostgresMeter) Add(key string, amount int, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), costBudgetMeterTimeout)
	defer cancel()
	var total int
	if err := m.db.QueryRowContext(ctx, addSQL, key, amount).Scan(&total); err != nil {
		return 0, fmt.Errorf("add cost budget amount: %w", err)
	}
	return total, nil
}

func (m *PostgresMeter) Current(key string, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), costBudgetMeterTimeout)
	defer cancel()
	var total int
	err := m.db.QueryRowContext(ctx, currentSQL, key).Scan(&total)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read cost budget total: %w", err)
	}
	return total, nil
}

// ListNearCeiling satisfies domain.Lister -- an optional, dashboard-only
// capability, not part of Meter itself (see domain.Lister's doc comment).
// Returns up to limit entries, ordered by total descending. Unlike
// Add/Current, a query error here degrades to an empty result (logged,
// not returned) rather than failing open/closed -- this backs a read-only
// dashboard view, not an enforcement decision, so there is no "fail open"
// security posture to preserve.
func (m *PostgresMeter) ListNearCeiling(limit int) []domain.Entry {
	ctx, cancel := context.WithTimeout(context.Background(), costBudgetMeterTimeout)
	defer cancel()
	rows, err := m.db.QueryContext(ctx, listNearCeilingSQL, limit)
	if err != nil {
		m.logger.Error("list cost budget counters near ceiling", "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	entries := make([]domain.Entry, 0, limit)
	for rows.Next() {
		var e domain.Entry
		if err := rows.Scan(&e.Key, &e.Total); err != nil {
			m.logger.Error("scan cost budget counter row", "error", err)
			return nil
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		m.logger.Error("iterate cost budget counter rows", "error", err)
		return nil
	}
	return entries
}
