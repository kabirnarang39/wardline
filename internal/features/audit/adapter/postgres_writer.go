package adapter

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/audit/domain"
)

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

const insertSQL = `
INSERT INTO audit_entries (timestamp, identity, tool, decision, latency_ms, reason, trace_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

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

	if err := db.Ping(); err != nil {
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

	if _, err := db.Exec(createTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create audit_entries table: %w", err)
	}

	return &PostgresWriter{db: db}, nil
}

// Write implements domain.Writer.
func (w *PostgresWriter) Write(e domain.Entry) error {
	_, err := w.db.Exec(insertSQL, e.Timestamp, e.Identity, e.Tool, e.Decision, e.LatencyMS, e.Reason, e.TraceID)
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
