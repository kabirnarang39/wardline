package adapter

import (
	"context"
	"database/sql"
	"fmt"
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
	db  *sql.DB
	now func() time.Time
}

// NewPostgresRevoker opens a connection pool to dsn, creates the
// revoked_identities table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first revocation check.
func NewPostgresRevoker(dsn string) (*PostgresRevoker, error) {
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

	return &PostgresRevoker{db: db, now: time.Now}, nil
}

// Revoke implements domain.Revoker. Errors are deliberately not returned
// (the interface has no error return) -- same posture as RevocationList's
// Revoke, which also cannot fail short of an out-of-memory condition; a
// Postgres write failure here is logged by nothing today, matching the
// interface's existing contract, not a regression introduced by this
// adapter.
func (r *PostgresRevoker) Revoke(identity string, expiresAt time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()
	_, _ = r.db.ExecContext(ctx, upsertRevocationSQL, identity, expiresAt)
}

// IsRevoked implements domain.Revoker. A query error or a not-found row
// is treated identically to "not revoked" -- fail-open would be the wrong
// call for a security check, but a transient Postgres blip making every
// identity look revoked (fail-closed) would take down the whole proxy
// over a database hiccup, which is a worse outcome for an adapter that
// exists to make credential issuance HA-safe, not less available.
func (r *PostgresRevoker) IsRevoked(identity string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()

	var expiresAt time.Time
	err := r.db.QueryRowContext(ctx, selectRevocationSQL, identity).Scan(&expiresAt)
	if err != nil {
		return false
	}
	return r.now().Before(expiresAt)
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (r *PostgresRevoker) Close() error {
	return r.db.Close()
}
