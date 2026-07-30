package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/tenant"
)

// writeTimeout bounds every Postgres operation (the startup Ping and every
// per-request INSERT) so a blackholed connection (firewall drop, NAT
// idle-timeout, failover) degrades to a bounded error instead of hanging
// the calling goroutine forever — with SetMaxOpenConns(10), an unbounded
// hang here would eventually block every request the proxy serves, not
// just fail one audit write.
const writeTimeout = 5 * time.Second

// createTableSQL is run once, idempotently, by NewPostgresWriter. One
// table, no migration framework — see
// docs/superpowers/specs/2026-07-27-postgres-storage-design.md "Scope"
// for why a migration tool isn't introduced for a single, unchanging
// schema.
const createTableSQL = `
CREATE TABLE IF NOT EXISTS audit_entries (
	id BIGSERIAL PRIMARY KEY,
	timestamp TIMESTAMPTZ NOT NULL,
	identity TEXT NOT NULL,
	tool TEXT NOT NULL,
	decision TEXT NOT NULL,
	latency_ms BIGINT NOT NULL,
	reason TEXT,
	trace_id TEXT
)`

// createTimestampIndexSQL indexes the realistic audit-trail query columns
// (recency, filtering by actor) — the primary key alone only serves
// lookup-by-id, which isn't how an audit trail is queried in practice.
const createTimestampIndexSQL = `
CREATE INDEX IF NOT EXISTS audit_entries_timestamp_idx ON audit_entries (timestamp DESC)`

// addTenantColumnSQL and createTenantIndexSQL are additive migrations
// against a table that may already exist and be populated (from a
// deployment predating this task) -- ADD COLUMN ... NOT NULL DEFAULT
// backfills every pre-existing row with 'default' rather than leaving it
// NULL or empty, so a row written before this migration ran still reads
// back with a real tenant, never an empty string. Same
// idempotent-at-construction posture as createTableSQL /
// createTimestampIndexSQL, run every time NewPostgresWriter is called so
// a replica that starts against an already-migrated database is a no-op.
const addTenantColumnSQL = `
ALTER TABLE audit_entries ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT 'default'`

const createTenantIndexSQL = `
CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant ON audit_entries (tenant)`

const insertSQL = `
INSERT INTO audit_entries (timestamp, identity, tenant, tool, decision, latency_ms, reason, trace_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// PostgresWriter is a domain.Writer backed by a real Postgres database —
// a durable, SQL-queryable alternative to JSONLWriter, wired in when the
// postgres_storage feature flag is on. Every Write is a synchronous
// INSERT on the request path — see the design spec's "Error handling"
// section for why this is an accepted default (Postgres round-trip
// latency for a co-located database is small next to the JSON-RPC
// parsing and policy evaluation Wardline already does per request), not
// an oversight; a buffered/batched writer is the upgrade path if an
// operator's Postgres is meaningfully farther away.
type PostgresWriter struct {
	db *sql.DB
}

// NewPostgresWriter opens a connection pool to dsn, creates the
// audit_entries table if it doesn't already exist, and pings the
// connection — a bad DSN or unreachable database fails here, at
// construction time, not on the first proxied request.
func NewPostgresWriter(dsn string) (*PostgresWriter, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	// Conservative fixed defaults for a single-table audit sink, not
	// tuned for high throughput — the design doc's "Explicitly out of
	// scope" section defers exposing pool-tuning knobs in config this
	// cycle, so these bounds aren't operator-overridable yet.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create audit_entries table: %w", err)
	}

	indexCtx, indexCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer indexCancel()
	if _, err := db.ExecContext(indexCtx, createTimestampIndexSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create audit_entries timestamp index: %w", err)
	}

	tenantColCtx, tenantColCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer tenantColCancel()
	if _, err := db.ExecContext(tenantColCtx, addTenantColumnSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("add audit_entries tenant column: %w", err)
	}

	tenantIdxCtx, tenantIdxCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer tenantIdxCancel()
	if _, err := db.ExecContext(tenantIdxCtx, createTenantIndexSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create audit_entries tenant index: %w", err)
	}

	return &PostgresWriter{db: db}, nil
}

// Write implements domain.Writer.
func (w *PostgresWriter) Write(e domain.Entry) error {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	_, err := w.db.ExecContext(ctx, insertSQL, e.Timestamp, e.Identity, e.Tenant, e.Tool, e.Decision, e.LatencyMS, e.Reason, e.TraceID)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (w *PostgresWriter) Close() error {
	return w.db.Close()
}

// queryTimeout bounds Query, and is deliberately much larger than
// writeTimeout: a write is a single-row INSERT on the request path, but a
// Query is an operator-chosen range scan over the whole audit trail —
// a quarter's evidence export on a busy proxy is millions of rows, which
// a 5-second deadline aborts partway through for no good reason. This is
// still a bound, not "no deadline": a blackholed connection must fail,
// not hang the CLI forever.
const queryTimeout = 5 * time.Minute

const querySQL = `
SELECT timestamp, identity, tenant, tool, decision, latency_ms, reason, trace_id
FROM audit_entries
WHERE timestamp >= $1 AND timestamp < $2
ORDER BY timestamp`

// Query implements domain.Reader.
func (w *PostgresWriter) Query(ctx context.Context, from, to time.Time) ([]domain.Entry, error) {
	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := w.db.QueryContext(queryCtx, querySQL, from, to)
	if err != nil {
		return nil, fmt.Errorf("query audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []domain.Entry
	for rows.Next() {
		var e domain.Entry
		var reason, traceID sql.NullString
		if err := rows.Scan(&e.Timestamp, &e.Identity, &e.Tenant, &e.Tool, &e.Decision, &e.LatencyMS, &reason, &traceID); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if e.Tenant == "" {
			// Defensive: the column is NOT NULL DEFAULT 'default' and the
			// migration backfills existing rows, so this shouldn't be
			// reachable in practice -- kept anyway so a row that somehow
			// has an empty tenant never surfaces as unscoped rather than
			// defaulted.
			e.Tenant = tenant.Default
		}
		e.Reason = reason.String
		e.TraceID = traceID.String
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit entries: %w", err)
	}
	return entries, nil
}

var _ domain.Reader = (*PostgresWriter)(nil)
