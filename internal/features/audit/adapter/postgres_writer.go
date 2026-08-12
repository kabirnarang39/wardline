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

// writeTimeout bounds every Postgres operation this adapter performs (the
// startup table/index creation and every per-request INSERT) so a
// blackholed connection (firewall drop, NAT idle-timeout, failover)
// degrades to a bounded error instead of hanging the calling goroutine
// forever — an unbounded hang here would eventually block every request
// the proxy serves, not just fail one audit write.
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

// NewPostgresWriter creates the audit_entries table on db if it doesn't
// already exist — db is expected already open and pinged (see
// pgpool.Open, called once in cmd/wardline/main.go and shared across
// every Postgres-backed feature) — a bad db fails here, at construction
// time, not on the first proxied request.
func NewPostgresWriter(db *sql.DB) (*PostgresWriter, error) {
	createCtx, createCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createTableSQL); err != nil {
		return nil, fmt.Errorf("create audit_entries table: %w", err)
	}

	indexCtx, indexCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer indexCancel()
	if _, err := db.ExecContext(indexCtx, createTimestampIndexSQL); err != nil {
		return nil, fmt.Errorf("create audit_entries timestamp index: %w", err)
	}

	tenantColCtx, tenantColCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer tenantColCancel()
	if _, err := db.ExecContext(tenantColCtx, addTenantColumnSQL); err != nil {
		return nil, fmt.Errorf("add audit_entries tenant column: %w", err)
	}

	tenantIdxCtx, tenantIdxCancel := context.WithTimeout(context.Background(), writeTimeout)
	defer tenantIdxCancel()
	if _, err := db.ExecContext(tenantIdxCtx, createTenantIndexSQL); err != nil {
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

const deleteOlderThanSQL = `DELETE FROM audit_entries WHERE timestamp < $1`

// Purge implements domain.Purger. Uses queryTimeout, not writeTimeout: a
// bulk DELETE over a large retention backlog is closer in shape to a
// range-scan Query than a single-row Write.
func (w *PostgresWriter) Purge(ctx context.Context, cutoff time.Time) (int, error) {
	purgeCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	res, err := w.db.ExecContext(purgeCtx, deleteOlderThanSQL, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete audit entries older than %s: %w", cutoff, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted audit entries: %w", err)
	}
	return int(n), nil
}

var _ domain.Purger = (*PostgresWriter)(nil)

// liveTimeout bounds Since -- it sits on the dashboard's live-audit
// polling path (GET /dashboard/api/audit), not a one-shot CLI query, so
// it gets writeTimeout's tighter bound rather than queryTimeout's
// multi-minute one: a slow poll should fail fast and let the dashboard
// retry, not hang the request.
const liveTimeout = 5 * time.Second

const sinceSQLUnfiltered = `
SELECT id, timestamp, identity, tenant, tool, decision, latency_ms, reason, trace_id
FROM audit_entries
WHERE id > $1
ORDER BY id ASC
LIMIT $2`

const sinceSQLTenantFiltered = `
SELECT id, timestamp, identity, tenant, tool, decision, latency_ms, reason, trace_id
FROM audit_entries
WHERE id > $1 AND tenant = $2
ORDER BY id ASC
LIMIT $3`

// LiveEntryRow is one row Since returns -- a plain struct, not
// dashboard/domain.LiveEntry: audit/adapter must not import a sibling
// feature's domain package (feature-sliced Clean Architecture -- see
// CLAUDE.md), so the composition root (cmd/wardline/main.go, which
// already imports both features to wire them together) adapts this
// into dashboard/domain.LiveEntry itself. Field names and order match
// dashboard/domain.LiveEntry's exactly to make that adaptation
// mechanical.
type LiveEntryRow struct {
	ID        int64
	Timestamp time.Time
	Identity  string
	Tenant    string
	Tool      string
	Decision  string
	LatencyMS int64
	Reason    string
	TraceID   string
}

// Since returns every audit_entries row with id > afterID (optionally
// scoped to tenantFilter, "" meaning unfiltered), oldest first, capped
// at limit -- the cluster-wide counterpart to
// dashboardusecase.RingBuffer.Since's in-memory, per-replica version.
// Because every replica's PostgresWriter.Write inserts into the SAME
// shared audit_entries table (see this file's own doc comment on
// buildAuditSink), any replica's Since call sees every OTHER replica's
// audit entries too, not just its own -- closing the cluster-wide
// live-audit-aggregation gap RingBuffer alone has no way to close (it
// is, by construction, one process's own in-memory slice).
//
// A query failure returns the error rather than failing open to an
// empty slice -- unlike Revoker/Limiter's own fail-open postures (a
// security decision degrading safely), a dropped live-audit poll has no
// safety property to preserve by failing open; the caller (main.go's
// adapter shim) logs it and the dashboard's next poll simply retries.
func (w *PostgresWriter) Since(afterID int64, limit int, tenantFilter string) ([]LiveEntryRow, error) {
	ctx, cancel := context.WithTimeout(context.Background(), liveTimeout)
	defer cancel()

	var rows *sql.Rows
	var err error
	if tenantFilter == "" {
		rows, err = w.db.QueryContext(ctx, sinceSQLUnfiltered, afterID, limit)
	} else {
		rows, err = w.db.QueryContext(ctx, sinceSQLTenantFiltered, afterID, tenantFilter, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("query live audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []LiveEntryRow
	for rows.Next() {
		var e LiveEntryRow
		var reason, traceID sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Identity, &e.Tenant, &e.Tool, &e.Decision, &e.LatencyMS, &reason, &traceID); err != nil {
			return nil, fmt.Errorf("scan live audit entry: %w", err)
		}
		e.Reason = reason.String
		e.TraceID = traceID.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate live audit entries: %w", err)
	}
	return out, nil
}
