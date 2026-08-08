package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// blockStoreTimeout bounds every Postgres operation this adapter
// performs. Check sits on the request path (every proxied tool call when
// auto_block is on), so a blackholed connection must degrade to a
// bounded error -- and Check fails OPEN on that error (see Check),
// matching PostgresLimiter/PostgresRevoker's established precedent:
// availability over strictness on the hot path, since a DB hiccup must
// not accidentally block every identity at once.
const blockStoreTimeout = 5 * time.Second

const createBlockedIdentitiesTableSQL = `
CREATE TABLE IF NOT EXISTS blocked_identities (
	key TEXT PRIMARY KEY,
	tenant TEXT NOT NULL,
	identity TEXT NOT NULL,
	reason TEXT NOT NULL,
	blocked_since TIMESTAMPTZ NOT NULL,
	blocked_until TIMESTAMPTZ NOT NULL
)`

// blockUpsertSQL records or refreshes a block. ON CONFLICT overwrites an
// existing block for the same (tenant, identity) -- a re-block simply
// extends the window from the new "now", matching the in-memory
// BlockChecker.Block, which overwrites its map entry unconditionally.
const blockUpsertSQL = `
INSERT INTO blocked_identities (key, tenant, identity, reason, blocked_since, blocked_until)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (key) DO UPDATE SET
	reason = EXCLUDED.reason,
	blocked_since = EXCLUDED.blocked_since,
	blocked_until = EXCLUDED.blocked_until`

// blockCheckSQL reads a still-active block for one key. A row whose
// blocked_until has already passed reads as "not blocked" via the
// WHERE clause, so no separate expiry step is needed -- the same
// compare-against-now-directly semantics the in-memory store uses.
const blockCheckSQL = `
SELECT reason, blocked_until FROM blocked_identities
WHERE key = $1 AND blocked_until > $2`

// blockDeleteSQL removes a block by key. Returns whether a still-active
// row was deleted, so Unblock can report "was actually blocked" the same
// way the in-memory store does.
const blockDeleteActiveSQL = `DELETE FROM blocked_identities WHERE key = $1 AND blocked_until > $2`
const blockDeleteAnySQL = `DELETE FROM blocked_identities WHERE key = $1`

// blockListSQL reads every still-active block, optionally tenant-scoped.
// A NULL/"" $1 means unfiltered (the COALESCE makes an empty filter match
// every tenant), so one query serves both the filtered and unfiltered
// dashboard views.
const blockListSQL = `
SELECT tenant, identity, reason, blocked_since, blocked_until FROM blocked_identities
WHERE blocked_until > $1 AND ($2 = '' OR tenant = $2)
ORDER BY blocked_since`

// blockReapSQL deletes rows whose block has already expired -- storage
// hygiene run opportunistically (see reapInterval), the SQL mirror of
// the in-memory store's StartBlockGC ticker. An expired row already
// reads as "not blocked" everywhere via the blocked_until > now guards,
// so this is purely about not letting the table grow unboundedly.
const blockReapSQL = `DELETE FROM blocked_identities WHERE blocked_until <= $1`

// reapInterval is how many Block calls pass between opportunistic sweeps
// of expired rows -- matches PostgresLimiter's budgetReapInterval
// rationale. Block (not Check) drives the counter: writes are far rarer
// than checks, and a sweep on every check would add a bounded DELETE to
// the hot path for no benefit the write-path sweep doesn't already give.
const reapInterval = 256

// PostgresBlockStore is an anomaly/domain.Blocker backed by a real
// Postgres database -- the HA-safe alternative to the in-memory
// BlockChecker, wired in when both anomaly_detection and postgres_storage
// are on. A block written by any replica is visible to every replica on
// its next Check, so a blocked identity can't dodge the block by being
// load-balanced to a different pod. The block DURATION is held Go-side
// (from config, like BlockChecker's cfg.BlockDurationSeconds); only the
// block STATE moves to Postgres.
type PostgresBlockStore struct {
	db            *sql.DB
	blockDuration time.Duration
	logger        *slog.Logger
	now           func() time.Time

	blockCalls uint64
}

// NewPostgresBlockStore opens a connection pool to dsn, creates the
// blocked_identities table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first Check. logger surfaces
// Check/Block query failures that would otherwise be silent -- may be
// nil (no method panics on a nil logger).
func NewPostgresBlockStore(dsn string, blockDuration time.Duration, logger *slog.Logger) (*PostgresBlockStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createBlockedIdentitiesTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create blocked_identities table: %w", err)
	}

	return &PostgresBlockStore{db: db, blockDuration: blockDuration, logger: logger, now: time.Now}, nil
}

func (s *PostgresBlockStore) Block(identity, tenantName, reason string) {
	since := s.now()
	until := since.Add(s.blockDuration)
	ctx, cancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, blockUpsertSQL, tenant.Key(tenantName, identity), tenantName, identity, reason, since, until); err != nil {
		// A failed Block is logged, not retried: the detector already
		// decided to block, but a shared-store write failure must not
		// crash the request path. The identity simply isn't blocked
		// cluster-wide this round -- the same fail-toward-availability
		// posture Check takes, and the next anomaly that re-triggers the
		// block will try the write again.
		if s.logger != nil {
			s.logger.Warn("failed to persist auto-block; identity not blocked cluster-wide this round", "identity", identity, "tenant", tenantName, "error", err)
		}
		return
	}

	s.blockCalls++
	if s.blockCalls%reapInterval == 0 {
		s.reapExpired()
	}
}

func (s *PostgresBlockStore) Check(identity, tenantName string, now time.Time) domain.BlockVerdict {
	ctx, cancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer cancel()
	var reason string
	var until time.Time
	err := s.db.QueryRowContext(ctx, blockCheckSQL, tenant.Key(tenantName, identity), now).Scan(&reason, &until)
	if err == sql.ErrNoRows {
		return domain.BlockVerdict{Allowed: true}
	}
	if err != nil {
		// Fail open: a DB hiccup must not block every identity at once
		// (the same reasoning PostgresLimiter.Allow and
		// PostgresRevoker.IsRevoked already apply on this hot path).
		if s.logger != nil {
			s.logger.Warn("auto-block check failed open: treating as not blocked", "identity", identity, "tenant", tenantName, "error", err)
		}
		return domain.BlockVerdict{Allowed: true}
	}
	return domain.BlockVerdict{Allowed: false, RetryAfter: until.Sub(now), Reason: reason}
}

func (s *PostgresBlockStore) Unblock(identity, tenantName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer cancel()
	// Delete only if still active, to report the same "was actually
	// blocked" result the in-memory store does -- then a second,
	// unconditional delete cleans up an already-expired row for hygiene
	// (its result doesn't change the return value).
	res, err := s.db.ExecContext(ctx, blockDeleteActiveSQL, tenant.Key(tenantName, identity), s.now())
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to unblock identity", "identity", identity, "tenant", tenantName, "error", err)
		}
		return false
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Nothing active was deleted; clean up any expired leftover row.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), blockStoreTimeout)
		defer cleanupCancel()
		_, _ = s.db.ExecContext(cleanupCtx, blockDeleteAnySQL, tenant.Key(tenantName, identity))
	}
	return n > 0
}

func (s *PostgresBlockStore) List(tenantFilter string) []domain.BlockedEntry {
	ctx, cancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, blockListSQL, s.now(), tenantFilter)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("failed to list blocked identities", "error", err)
		}
		return nil
	}
	defer func() { _ = rows.Close() }()

	var entries []domain.BlockedEntry
	for rows.Next() {
		var e domain.BlockedEntry
		if err := rows.Scan(&e.Tenant, &e.Identity, &e.Reason, &e.BlockedSince, &e.BlockedUntil); err != nil {
			if s.logger != nil {
				s.logger.Warn("failed to scan blocked identity row", "error", err)
			}
			return entries
		}
		entries = append(entries, e)
	}
	return entries
}

// reapExpired deletes already-expired rows. Logged-and-swallowed on
// failure, retried on the next sweep -- storage hygiene, not correctness
// (expired rows already read as not-blocked everywhere).
func (s *PostgresBlockStore) reapExpired() {
	ctx, cancel := context.WithTimeout(context.Background(), blockStoreTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, blockReapSQL, s.now()); err != nil && s.logger != nil {
		s.logger.Warn("blocked_identities sweep failed; expired rows retried on next sweep", "error", err)
	}
}

// Close releases the connection pool during graceful shutdown.
func (s *PostgresBlockStore) Close() error {
	return s.db.Close()
}

var _ domain.Blocker = (*PostgresBlockStore)(nil)
