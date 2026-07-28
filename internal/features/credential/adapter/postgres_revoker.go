package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// revokerTimeout bounds every Postgres operation this adapter performs --
// same rationale and same value as audit/adapter.PostgresWriter's
// writeTimeout: Revoke/IsRevoked sit on the request path (identity
// resolution and /credentials/revoke respectively), so a blackholed
// connection must degrade to a bounded error, not hang the caller.
const revokerTimeout = 5 * time.Second

const createRevokedIdentitiesTableSQL = `
CREATE TABLE IF NOT EXISTS revoked_identities (
	identity TEXT PRIMARY KEY,
	expires_at TIMESTAMPTZ NOT NULL
)`

const upsertRevocationSQL = `
INSERT INTO revoked_identities (identity, expires_at)
VALUES ($1, $2)
ON CONFLICT (identity) DO UPDATE SET expires_at = EXCLUDED.expires_at`

const selectRevocationSQL = `
SELECT expires_at FROM revoked_identities WHERE identity = $1`

// PostgresRevoker is a credential/domain.Revoker backed by a real
// Postgres database -- the HA-safe alternative to RevocationList, wired
// in when both credential_issuance and postgres_storage are on. Every
// Revoke/IsRevoked call reaches the same shared database every replica
// connects to, so a revocation made through one replica is honored by
// every other replica on its very next check -- unlike RevocationList,
// whose map is scoped to a single process. Mirrors
// audit/adapter.PostgresWriter's connection-pool and idempotent-table
// pattern exactly.
type PostgresRevoker struct {
	db     *sql.DB
	now    func() time.Time
	logger *slog.Logger
}

// NewPostgresRevoker opens a connection pool to dsn, creates the
// revoked_identities table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first revocation check. logger is used
// to surface IsRevoked query failures that would otherwise be
// indistinguishable from a genuine "not revoked" result (see IsRevoked).
func NewPostgresRevoker(dsn string, logger *slog.Logger) (*PostgresRevoker, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createRevokedIdentitiesTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create revoked_identities table: %w", err)
	}

	return &PostgresRevoker{db: db, now: time.Now, logger: logger}, nil
}

// Revoke implements domain.Revoker. Unlike RevocationList's Revoke (an
// in-memory map write that cannot fail), a Postgres write genuinely can
// fail -- the error is returned so a caller (ultimately
// /credentials/revoke's HTTP handler) can tell an operator the
// revocation did NOT take effect, instead of returning success for a
// security action that never happened.
func (r *PostgresRevoker) Revoke(identity string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()
	if _, err := r.db.ExecContext(ctx, upsertRevocationSQL, identity, expiresAt); err != nil {
		return fmt.Errorf("write revocation for %q: %w", identity, err)
	}
	return nil
}

// IsRevoked implements domain.Revoker. A genuinely not-found row
// (sql.ErrNoRows) is the real, silent "not revoked" case and is never
// logged -- that's the expected, high-frequency result for every
// non-revoked identity on every request. Any OTHER query error (a
// connection failure, a timeout, etc.) is logged at Warn before falling
// back to "not revoked": fail-open is still the right call here (a
// transient Postgres blip making every identity look revoked would take
// down the whole proxy over a database hiccup), but a fail-open decision
// that's indistinguishable in the logs from the ordinary case is a
// silent security gap, not an acceptable trade-off -- an operator
// investigating "why did a revoked token still work" needs to be able to
// find this in the logs.
func (r *PostgresRevoker) IsRevoked(identity string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()

	var expiresAt time.Time
	err := r.db.QueryRowContext(ctx, selectRevocationSQL, identity).Scan(&expiresAt)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) && r.logger != nil {
			r.logger.Warn("revocation check failed open: treating as not-revoked", "identity", identity, "error", err)
		}
		return false
	}
	return r.now().Before(expiresAt)
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (r *PostgresRevoker) Close() error {
	return r.db.Close()
}
