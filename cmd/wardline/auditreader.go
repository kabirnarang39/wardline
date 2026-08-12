package main

import (
	"fmt"
	"io"
	"log/slog"

	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
)

// newAuditReader builds the audit.Reader an offline command should query,
// selecting postgres or JSONL by the same features.postgres_storage
// precedence buildAuditSink applies for serve (postgres wins, audit.output
// is ignored), and rejecting audit.output "stdout" (not queryable, no
// history to read back). Returns the reader; when a JSONL file was used,
// the *auditadapter.JSONLReader too (its SkippedLines count is
// operator-relevant after the caller's Query call runs, nil when postgres
// was used instead); and an io.Closer for the caller to defer-close when
// non-nil (the pool this call opened on the postgres path, nil on the
// JSONL path -- each Query call there opens and closes its own file
// handle, nothing to hold open).
//
// This is a one-shot CLI command's own short-lived pool (infer-policy,
// export-evidence), distinct from serve's long-running shared pool (see
// internal/platform/pgpool and cmd/wardline/main.go's runServe) -- a CLI
// invocation only ever touches audit here, never multiple Postgres-backed
// features in the same process, so there's no pool to share.
//
// commandName appears in the stdout-rejection error message, so the
// operator sees which command they ran (e.g. "export-evidence",
// "infer-policy").
//
// On the postgres path, NewPostgresWriter runs CREATE TABLE/INDEX IF NOT
// EXISTS on connect, so every caller -- read-only ones included -- needs
// the same DDL-capable DSN serve uses; a SELECT-only role can't run it.
// See README.md "Compliance evidence export" and "Auto-generated sandbox
// policy". A dedicated read-only connector is deferred: it also needs a
// separate DSN config field to be useful, which is a design change, not a
// bug fix.
func newAuditReader(logger *slog.Logger, featureFlags flags.Provider, cfg config.AuditConfig, commandName string) (auditdomain.Reader, *auditadapter.JSONLReader, io.Closer, error) {
	if featureFlags.Enabled("postgres_storage") {
		if cfg.Output != "" {
			logger.Info("audit.output is set but features.postgres_storage is on; querying postgres and ignoring audit.output",
				"output", cfg.Output)
		}
		db, err := pgpool.Open(cfg.PostgresDSN, cfg.PostgresMaxOpenConns)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		pw, err := auditadapter.NewPostgresWriter(db)
		if err != nil {
			_ = db.Close()
			return nil, nil, nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		return pw, nil, db, nil
	}
	if cfg.Output == "stdout" {
		return nil, nil, nil, fmt.Errorf("audit trail is not queryable when audit.output is stdout -- configure a file path or features.postgres_storage to use %s", commandName)
	}
	jsonlReader := auditadapter.NewJSONLReader(cfg.Output)
	return jsonlReader, jsonlReader, nil, nil
}
