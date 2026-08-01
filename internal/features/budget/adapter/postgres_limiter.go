package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/budget/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// budgetLimiterTimeout bounds every Postgres operation this adapter
// performs -- same rationale and same value as
// credential/adapter.revokerTimeout: Allow sits on the request path
// (every proxied tool call, when budget_enforcement is on), so a
// blackholed connection must degrade to a bounded error (and fail open,
// see Allow), not hang the caller.
const budgetLimiterTimeout = 5 * time.Second

const createBudgetBucketsTableSQL = `
CREATE TABLE IF NOT EXISTS budget_buckets (
	key TEXT PRIMARY KEY,
	window_start TIMESTAMPTZ NOT NULL,
	count INTEGER NOT NULL,
	allowed BOOLEAN NOT NULL
)`

// checkAndAdvanceSQL is the atomic fixed-window check-and-increment this
// whole adapter depends on -- one INSERT ... ON CONFLICT DO UPDATE ...
// RETURNING round trip, empirically verified against a real Postgres 16
// instance (see docs/superpowers/specs/2026-08-01-distributed-budget-counters-design.md)
// for sequential admission-then-denial, window-expiry reset, and 50-way
// concurrent-writer correctness before being written here.
//
// allowed is a real, persisted column, not merely something computed in
// RETURNING -- it exists as a data-smuggling channel. Postgres's ON
// CONFLICT DO UPDATE SET clause can see the pre-update row (bare/
// table-qualified column names resolve to OLD values there), but
// RETURNING can only see the FINAL row, so "was this row just reset,
// incremented, or left alone because already at the limit" has to be
// decided once inside SET and read back through a real column, not
// recomputed in RETURNING (which would only ever see the
// already-decided outcome and couldn't tell "count == limit because we
// just incremented to it" apart from "count == limit because we left it
// alone").
//
// $4 is the window length in microseconds, not whole seconds -- an
// earlier version of this query passed int64(window/time.Second) and
// multiplied by INTERVAL '1 second', which integer-truncates any
// sub-second window (e.g. 200ms) to 0, making the expiry condition
// (window_start + 0 <= now) trivially true on every call and resetting
// the bucket on every single request instead of once per window.
// Microsecond granularity keeps the same integer-interval-arithmetic
// shape while giving Wardline's configurable windows (which can be
// sub-second in tests) exact, non-truncated comparisons.
const checkAndAdvanceSQL = `
INSERT INTO budget_buckets (key, window_start, count, allowed)
VALUES ($1, $2, 1, true)
ON CONFLICT (key) DO UPDATE SET
	window_start = CASE
		WHEN budget_buckets.window_start + ($4 * INTERVAL '1 microsecond') <= $2 THEN $2
		ELSE budget_buckets.window_start
	END,
	count = CASE
		WHEN budget_buckets.window_start + ($4 * INTERVAL '1 microsecond') <= $2 THEN 1
		WHEN budget_buckets.count < $3 THEN budget_buckets.count + 1
		ELSE budget_buckets.count
	END,
	allowed = CASE
		WHEN budget_buckets.window_start + ($4 * INTERVAL '1 microsecond') <= $2 THEN true
		WHEN budget_buckets.count < $3 THEN true
		ELSE false
	END
RETURNING window_start, count, allowed`

// PostgresLimiter is a budget/domain.Limiter backed by a real Postgres
// database -- the HA-safe alternative to InMemoryLimiter, wired in when
// both budget_enforcement and postgres_storage are on. Every Allow call
// reaches the same shared database every replica connects to, so a
// caller's budget is enforced across the whole fleet instead of
// per-replica. tenantLimits/toolLimits are added in a later task; this
// task's Allow checks only the identity bucket.
type PostgresLimiter struct {
	db                *sql.DB
	requestsPerWindow int
	window            time.Duration
	logger            *slog.Logger
}

// NewPostgresLimiter opens a connection pool to dsn, creates the
// budget_buckets table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first Allow call. logger is used to
// surface Allow query failures that would otherwise be indistinguishable
// from the ordinary "within budget" result -- may be nil (Allow must not
// panic on a nil logger; see the "no logger" test).
func NewPostgresLimiter(dsn string, requestsPerWindow int, window time.Duration, logger *slog.Logger) (*PostgresLimiter, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), budgetLimiterTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), budgetLimiterTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createBudgetBucketsTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create budget_buckets table: %w", err)
	}

	return &PostgresLimiter{
		db:                db,
		requestsPerWindow: requestsPerWindow,
		window:            window,
		logger:            logger,
	}, nil
}

// checkAndAdvance runs the atomic upsert for one bucket key and returns
// the resulting domain.Verdict. The only error it returns is a genuine
// Postgres failure (connection, timeout) -- callers must fail open on a
// non-nil error, matching PostgresRevoker.IsRevoked's established
// precedent (see Allow).
func (l *PostgresLimiter) checkAndAdvance(key string, requestsPerWindow int, window time.Duration, now time.Time) (domain.Verdict, error) {
	ctx, cancel := context.WithTimeout(context.Background(), budgetLimiterTimeout)
	defer cancel()

	var windowStart time.Time
	var count int
	var allowed bool
	err := l.db.QueryRowContext(ctx, checkAndAdvanceSQL, key, now, requestsPerWindow, int64(window/time.Microsecond)).
		Scan(&windowStart, &count, &allowed)
	if err != nil {
		return domain.Verdict{}, err
	}

	if !allowed {
		return domain.Verdict{
			Allowed:    false,
			Reason:     fmt.Sprintf("rate limit exceeded: %d requests per %s window", requestsPerWindow, window),
			RetryAfter: windowStart.Add(window).Sub(now),
		}, nil
	}
	return domain.Verdict{Allowed: true, Reason: "within budget"}, nil
}

// Allow implements domain.Limiter. This task's version checks only the
// identity bucket -- keyed by tenant.Key(tenantName, identity), same
// composite-key collision-avoidance reasoning InMemoryLimiter's own
// identity bucket already uses, prefixed with "identity:" so a later
// task's tenant/tool buckets (sharing this same table) can never collide
// with an identity bucket's key regardless of what any tenant/tool/
// identity string contains -- the prefix is a fixed literal chosen by
// this code, never influenced by caller input.
func (l *PostgresLimiter) Allow(identity, tenantName, toolName string, now time.Time) domain.Verdict {
	key := "identity:" + tenant.Key(tenantName, identity)
	v, err := l.checkAndAdvance(key, l.requestsPerWindow, l.window, now)
	if err != nil {
		if l.logger != nil {
			l.logger.Warn("budget check failed open: treating as within budget", "identity", identity, "tenant", tenantName, "tool", toolName, "error", err)
		}
		return domain.Verdict{Allowed: true, Reason: fmt.Sprintf("budget check failed open: %v", err)}
	}
	return v
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (l *PostgresLimiter) Close() error {
	return l.db.Close()
}

var _ domain.Limiter = (*PostgresLimiter)(nil)
