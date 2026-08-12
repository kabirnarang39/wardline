package main

import (
	"path/filepath"
	"strings"
	"testing"

	auditdomain "github.com/kabirnarang39/wardline/internal/features/audit/domain"
	"github.com/kabirnarang39/wardline/internal/platform/config"
	"github.com/kabirnarang39/wardline/internal/platform/flags"
)

// discardLogger is defined in policypack_test.go (same package).

func TestNewAuditReader_StdoutOutputIsRejected(t *testing.T) {
	logger := discardLogger()
	featureFlags := flags.NewStaticProvider(nil)
	_, _, _, err := newAuditReader(logger, featureFlags, config.AuditConfig{Output: "stdout"}, "infer-policy")
	if err == nil {
		t.Fatal("expected an error for audit.output: stdout, got nil")
	}
	if !strings.Contains(err.Error(), "not queryable") {
		t.Errorf("expected error to mention 'not queryable', got: %v", err)
	}
	if !strings.Contains(err.Error(), "infer-policy") {
		t.Errorf("expected error to name the calling command 'infer-policy', got: %v", err)
	}
}

func TestNewAuditReader_FileOutputReturnsJSONLReaderForThatPath(t *testing.T) {
	logger := discardLogger()
	featureFlags := flags.NewStaticProvider(nil)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	reader, jsonlReader, closer, err := newAuditReader(logger, featureFlags, config.AuditConfig{Output: path}, "export-evidence")
	if err != nil {
		t.Fatalf("newAuditReader: %v", err)
	}
	if closer != nil {
		t.Error("expected a nil closer for the JSONL path -- each Query call opens and closes its own file handle")
	}
	if jsonlReader == nil {
		t.Fatal("expected a non-nil *auditadapter.JSONLReader for a file-path audit.output")
	}
	if reader != auditdomain.Reader(jsonlReader) {
		t.Error("expected the returned auditdomain.Reader to be the same JSONLReader instance")
	}
}

func TestNewAuditReader_PostgresStorageOn_BadDSNFailsFast(t *testing.T) {
	logger := discardLogger()
	featureFlags := flags.NewStaticProvider(map[string]bool{"postgres_storage": true})
	_, _, _, err := newAuditReader(logger, featureFlags, config.AuditConfig{PostgresDSN: "not-a-valid-dsn"}, "infer-policy")
	if err == nil {
		t.Fatal("expected an error for a malformed postgres DSN, got nil")
	}
	if !strings.Contains(err.Error(), "failed to connect to postgres") {
		t.Errorf("expected error to mention 'failed to connect to postgres', got: %v", err)
	}
}
