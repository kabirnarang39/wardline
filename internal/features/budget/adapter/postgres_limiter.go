package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
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

// budgetReapInterval is how many Allow calls pass between opportunistic
// sweeps of expired budget_buckets rows. 1000 matches
// evictionSweepInterval exactly -- this is the SQL mirror of
// InMemoryLimiter's own sweep, and for the same reason its doc comment
// gives: identity is trusted as-is, so every distinct identity a caller
// ever sends gets a row, and without a sweep the table grows forever.
// One bounded DELETE every 1000 requests is negligible next to the three
// round trips a single multi-tier Allow can already cost.
const budgetReapInterval = 1000

// reapExpiredBucketsSQL deletes rows whose window provably cannot still
// be live. A row does not record its own window length (the three tiers
// each carry their own configured window, and tenant/tool windows differ
// per name), so the sweep uses the LONGEST window configured on this
// limiter: any row untouched for longer than that is expired no matter
// which tier it belongs to. That is deliberately conservative in the
// safe direction -- a short-window row lingers a little past its expiry
// (costing only storage, since checkAndAdvance resets an expired row on
// next touch anyway), and a live row is never deleted, which would
// silently hand a caller a fresh budget.
//
// ponytail: sequential scan, no index on window_start -- the table is
// bounded by live identity cardinality once this sweep exists. Add an
// index if the sweep ever shows up in query timings.
const reapExpiredBucketsSQL = `DELETE FROM budget_buckets WHERE window_start + ($1 * INTERVAL '1 microsecond') <= $2`

// PostgresLimiter is a budget/domain.Limiter backed by a real Postgres
// database -- the HA-safe alternative to InMemoryLimiter, wired in when
// both budget_enforcement and postgres_storage are on. Every Allow call
// reaches the same shared database every replica connects to, so a
// caller's budget is enforced across the whole fleet instead of
// per-replica. tenantLimits/toolLimits stay exactly where
// InMemoryLimiter already keeps them -- Go-side maps populated once at
// construction from config -- only the bucket *state* moves to
// Postgres; there is nothing tenant/tool-specific to share across
// replicas except the counters themselves.
type PostgresLimiter struct {
	db                *sql.DB
	requestsPerWindow int
	window            time.Duration
	logger            *slog.Logger

	mu           sync.Mutex
	calls        uint64
	tenantLimits map[string]tenantLimit
	toolLimits   map[string]tenantLimit
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
		tenantLimits:      make(map[string]tenantLimit),
		toolLimits:        make(map[string]tenantLimit),
	}, nil
}

// SetTenantLimit configures an override rate for tenantName, consulted
// alongside (in addition to, not instead of) the identity bucket. A
// tenant with no override configured here is never checked against a
// tenant bucket at all -- Allow falls straight through to the next
// tier. Mirrors InMemoryLimiter.SetTenantLimit exactly.
func (l *PostgresLimiter) SetTenantLimit(tenantName string, requestsPerWindow int, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tenantLimits[tenantName] = tenantLimit{requestsPerWindow: requestsPerWindow, window: window}
}

// SetToolLimit configures an override rate for toolName, consulted
// alongside the identity and tenant buckets -- mirrors
// InMemoryLimiter.SetToolLimit exactly. A tool with no override
// configured here is never checked against a tool bucket at all.
func (l *PostgresLimiter) SetToolLimit(toolName string, requestsPerWindow int, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.toolLimits[toolName] = tenantLimit{requestsPerWindow: requestsPerWindow, window: window}
}

// SetDefaultLimit updates the global (non-override) rate limit in place,
// without resetting any identity's already-tracked usage in Postgres --
// mirrors InMemoryLimiter.SetDefaultLimit exactly. The bucket *state*
// lives in the budget_buckets table, keyed by identity/tenant/tool, and
// is untouched here -- only the threshold checkAndAdvance compares
// against changes.
func (l *PostgresLimiter) SetDefaultLimit(requestsPerWindow int, window time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requestsPerWindow = requestsPerWindow
	l.window = window
}

// ClearTenantLimit removes tenantName's override, reverting it to the
// global default -- mirrors InMemoryLimiter.ClearTenantLimit exactly.
// tenantLimits is a Go-side map populated from config (see PostgresLimiter's
// doc comment), not a Postgres row, so this is a plain map delete; the
// tenant's now-orphaned budget_buckets row (if any) is left for the
// ordinary reap sweep to clean up on its own schedule, same as any other
// expired row.
func (l *PostgresLimiter) ClearTenantLimit(tenantName string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tenantLimits, tenantName)
}

// ClearToolLimit mirrors ClearTenantLimit exactly, for the tool-tier
// override.
func (l *PostgresLimiter) ClearToolLimit(toolName string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.toolLimits, toolName)
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

// Allow implements domain.Limiter. Requires the tool bucket (if toolName
// has a configured override), the tenant bucket (if tenantName has a
// configured override), AND the identity bucket to all admit the
// request -- an AND, not an OR, tool checked first (cheapest to fail
// fast on a hot, narrow tool), then tenant, then identity -- exactly
// mirroring InMemoryLimiter.Allow's tier order and short-circuit
// behavior. A request denied by an earlier tier never touches a later,
// lower-priority bucket's budget. Bucket keys are prefixed with
// "tool:"/"tenant:"/"identity:" (fixed literals, never influenced by
// caller input) so the three tiers, sharing one table, can never
// collide regardless of what any tenant/tool/identity string contains.
// Any Postgres query error at ANY tier fails the whole call open
// immediately (matching PostgresRevoker.IsRevoked's precedent) rather
// than degrading tier-by-tier.
func (l *PostgresLimiter) Allow(identity, tenantName, toolName string, now time.Time) domain.Verdict {
	l.mu.Lock()
	toolLimit, hasToolLimit := l.toolLimits[toolName]
	tenantLimitVal, hasTenantLimit := l.tenantLimits[tenantName]
	l.calls++
	var reapWindow time.Duration
	if l.calls%budgetReapInterval == 0 {
		reapWindow = l.longestWindowLocked()
	}
	l.mu.Unlock()

	if reapWindow > 0 {
		l.reapExpired(reapWindow, now)
	}

	if hasToolLimit {
		v, err := l.checkAndAdvance("tool:"+toolName, toolLimit.requestsPerWindow, toolLimit.window, now)
		if err != nil {
			return l.failOpen(identity, tenantName, toolName, err)
		}
		if !v.Allowed {
			return v
		}
	}

	if hasTenantLimit {
		v, err := l.checkAndAdvance("tenant:"+tenantName, tenantLimitVal.requestsPerWindow, tenantLimitVal.window, now)
		if err != nil {
			return l.failOpen(identity, tenantName, toolName, err)
		}
		if !v.Allowed {
			return v
		}
	}

	key := "identity:" + tenant.Key(tenantName, identity)
	v, err := l.checkAndAdvance(key, l.requestsPerWindow, l.window, now)
	if err != nil {
		return l.failOpen(identity, tenantName, toolName, err)
	}
	return v
}

// failOpen logs and returns the shared fail-open Verdict every tier's
// query error produces -- factored out since Allow now has three call
// sites that need the identical behavior.
func (l *PostgresLimiter) failOpen(identity, tenantName, toolName string, err error) domain.Verdict {
	if l.logger != nil {
		l.logger.Warn("budget check failed open: treating as within budget", "identity", identity, "tenant", tenantName, "tool", toolName, "error", err)
	}
	return domain.Verdict{Allowed: true, FailedOpen: true, Reason: fmt.Sprintf("budget check failed open: %v", err)}
}

// longestWindowLocked returns the longest window configured across every
// tier — the safe expiry threshold for the sweep (see
// reapExpiredBucketsSQL). Called with l.mu already held, and only on a
// sweep boundary, so the map walks cost nothing on the ordinary path.
func (l *PostgresLimiter) longestWindowLocked() time.Duration {
	longest := l.window
	for _, limit := range l.tenantLimits {
		if limit.window > longest {
			longest = limit.window
		}
	}
	for _, limit := range l.toolLimits {
		if limit.window > longest {
			longest = limit.window
		}
	}
	return longest
}

// reapExpired deletes budget_buckets rows older than window. A failure
// here is logged and swallowed: the sweep is housekeeping, and failing
// the caller's request over it would turn a storage-growth concern into
// an availability one. The next sweep retries.
func (l *PostgresLimiter) reapExpired(window time.Duration, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), budgetLimiterTimeout)
	defer cancel()
	if _, err := l.db.ExecContext(ctx, reapExpiredBucketsSQL, int64(window/time.Microsecond), now); err != nil && l.logger != nil {
		l.logger.Warn("budget bucket sweep failed; expired rows will be retried on the next sweep", "error", err)
	}
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (l *PostgresLimiter) Close() error {
	return l.db.Close()
}

var _ domain.Limiter = (*PostgresLimiter)(nil)
