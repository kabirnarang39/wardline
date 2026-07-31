package main

import (
	"fmt"
	"log/slog"

	auditadapter "github.com/kabirnarang39/wardline/internal/features/audit/adapter"
	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
)

// newAuditReader builds the audit.Reader an offline command should query,
// selecting postgres or JSONL by the same features.postgres_storage
// precedence buildAuditSink applies for serve (postgres wins, audit.output
// is ignored), and rejecting audit.output "stdout" (not queryable, no
// history to read back). Returns the reader and, when a JSONL file was
// used, the *auditadapter.JSONLReader too (its SkippedLines count is
// operator-relevant after the caller's Query call runs); nil when
// postgres was used instead.
//
// The caller owns closing the returned reader: type-assert it to
// io.Closer and defer Close -- *auditadapter.PostgresWriter implements
// it, *auditadapter.JSONLReader does not need it (each Query call opens
// and closes its own file handle).
//
// commandName appears in the stdout-rejection error message, so the
// operator sees which command they ran (e.g. "export-evidence",
// "infer-policy").
func newAuditReader(logger *slog.Logger, featureFlags flags.Provider, cfg config.AuditConfig, commandName string) (auditdomain.Reader, *auditadapter.JSONLReader, error) {
	if featureFlags.Enabled("postgres_storage") {
		if cfg.Output != "" {
			logger.Info("audit.output is set but features.postgres_storage is on; querying postgres and ignoring audit.output",
				"output", cfg.Output)
		}
		pw, err := auditadapter.NewPostgresWriter(cfg.PostgresDSN)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		return pw, nil, nil
	}
	if cfg.Output == "stdout" {
		return nil, nil, fmt.Errorf("audit trail is not queryable when audit.output is stdout -- configure a file path or features.postgres_storage to use %s", commandName)
	}
	jsonlReader := auditadapter.NewJSONLReader(cfg.Output)
	return jsonlReader, jsonlReader, nil
}
