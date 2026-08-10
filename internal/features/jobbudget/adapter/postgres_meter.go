package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
)

// jobBudgetMeterTimeout bounds every Postgres operation this adapter
// performs -- same rationale as budget.PostgresLimiter's own timeout:
// Increment sits on the request path when job_budget is on, so a
// blackholed connection must degrade to a bounded error (the Checker
// then fails open), not hang the caller.
const jobBudgetMeterTimeout = 5 * time.Second

const createJobBudgetTableSQL = `
CREATE TABLE IF NOT EXISTS job_budget_counters (
	key TEXT PRIMARY KEY,
	count INTEGER NOT NULL
)`

// incrementSQL is the atomic upsert-and-increment this adapter depends on:
// one INSERT ... ON CONFLICT DO UPDATE ... RETURNING round trip, no
// separate read-then-write -- concurrent callers for the same key
// serialize on the row lock and each see a distinct, correctly
// incremented count. Simpler than budget.PostgresLimiter's version: there
// is no window to expire and reset here (a job's "reset" is its session
// id rotating, handled entirely by internal/platform/session, not by
// this table), so there is no CASE-based expiry branch to encode.
const incrementSQL = `
INSERT INTO job_budget_counters (key, count)
VALUES ($1, 1)
ON CONFLICT (key) DO UPDATE SET count = job_budget_counters.count + 1
RETURNING count`

// currentSQL reads without writing -- no INSERT, no ON CONFLICT. A
// never-seen key means sql.ErrNoRows, which Current below turns into
// (0, nil), matching InMemoryMeter's zero-value-for-absent-key behavior.
const currentSQL = `SELECT count FROM job_budget_counters WHERE key = $1`

// listNearCeilingSQL backs ListNearCeiling -- the dashboard-only,
// optional Lister capability (see domain.Lister's doc comment). Ordered
// by count descending so the callers nearest their ceiling sort first.
const listNearCeilingSQL = `SELECT key, count FROM job_budget_counters ORDER BY count DESC LIMIT $1`

// PostgresMeter satisfies domain.Meter, sharing counts across every
// Wardline replica pointed at the same DSN -- required for job_budget to
// mean anything behind a load balancer, the same reason
// budget.PostgresLimiter exists.
type PostgresMeter struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresMeter opens a connection pool to dsn and creates the
// job_budget_counters table if it doesn't already exist -- a bad DSN or
// unreachable database fails here, at construction time, not on the
// first Increment call.
func NewPostgresMeter(dsn string, logger *slog.Logger) (*PostgresMeter, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), jobBudgetMeterTimeout)
	defer cancel()
	if _, err := db.ExecContext(ctx, createJobBudgetTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create job_budget_counters table: %w", err)
	}
	return &PostgresMeter{db: db, logger: logger}, nil
}

func (m *PostgresMeter) Increment(key string, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), jobBudgetMeterTimeout)
	defer cancel()
	var count int
	if err := m.db.QueryRowContext(ctx, incrementSQL, key).Scan(&count); err != nil {
		return 0, fmt.Errorf("increment job budget counter: %w", err)
	}
	return count, nil
}

func (m *PostgresMeter) Current(key string, now time.Time) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), jobBudgetMeterTimeout)
	defer cancel()
	var count int
	err := m.db.QueryRowContext(ctx, currentSQL, key).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read job budget counter: %w", err)
	}
	return count, nil
}

// ListNearCeiling satisfies domain.Lister -- an optional, dashboard-only
// capability, not part of Meter itself (see domain.Lister's doc comment).
// Returns up to limit entries, ordered by count descending. Unlike
// Increment/Current, a query error here degrades to an empty result
// (logged, not returned) rather than failing open/closed -- this backs a
// read-only dashboard view, not an enforcement decision, so there is no
// "fail open" security posture to preserve.
func (m *PostgresMeter) ListNearCeiling(limit int) []domain.Entry {
	ctx, cancel := context.WithTimeout(context.Background(), jobBudgetMeterTimeout)
	defer cancel()
	rows, err := m.db.QueryContext(ctx, listNearCeilingSQL, limit)
	if err != nil {
		m.logger.Error("list job budget counters near ceiling", "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	entries := make([]domain.Entry, 0, limit)
	for rows.Next() {
		var e domain.Entry
		if err := rows.Scan(&e.Key, &e.Count); err != nil {
			m.logger.Error("scan job budget counter row", "error", err)
			return nil
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		m.logger.Error("iterate job budget counter rows", "error", err)
		return nil
	}
	return entries
}
