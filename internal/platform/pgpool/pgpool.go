// Package pgpool opens the ONE Postgres connection pool shared by every
// Postgres-backed feature (audit, credential revocation, refresh tokens,
// budget/job-budget/cost-budget, SCIM, anomaly baselines/blocks/tenant
// aggregates). Before this package existed, each of those features opened
// its own independent pool (typically 10 connections each) against the
// same database, so a replica running every Postgres-backed feature could
// hold tens of connections against a database whose default
// max_connections is often 100 -- and a Postgres-backed check that can't
// get a connection under that load fails OPEN (see
// docs-site/content/features/budget-enforcement.md's "Known
// limitations"), meaning the harder the load spike, the more likely
// enforcement is skipped. One shared pool applies a single, coherent
// backpressure budget across every feature instead of N independent ones
// that don't know about each other.
package pgpool

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// pingTimeout bounds Open's startup ping -- a bad DSN or unreachable
// database fails here, at construction time, not on the first request
// some feature makes against the pool.
const pingTimeout = 5 * time.Second

// defaultMaxOpenConns is used when maxOpenConns <= 0 -- see
// config.AuditConfig.PostgresMaxOpenConns's doc comment for the
// reasoning behind 25.
const defaultMaxOpenConns = 25

// Open opens dsn, pings it, and configures pooling -- the exact
// Open+Ping+SetMaxOpenConns/SetMaxIdleConns/SetConnMaxLifetime sequence
// every individual Postgres-backed adapter used to run for itself. The
// returned *sql.DB is handed to every Postgres-backed adapter constructor
// instead of each one calling this itself; its lifecycle (including
// Close) belongs to the caller (cmd/wardline/main.go), not to any one
// feature.
func Open(dsn string, maxOpenConns int) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if maxOpenConns <= 0 {
		maxOpenConns = defaultMaxOpenConns
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}
