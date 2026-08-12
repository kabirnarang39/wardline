package pgpool_test

import (
	"os"
	"testing"

	"github.com/kabirnarang39/wardline/internal/platform/pgpool"
)

// TestOpen_BadDSNFailsFast mirrors every individual Postgres-backed
// adapter's own TestNewPostgresXxx_BadDSNFailsFast (e.g.
// credential/adapter/postgres_revoker_test.go) -- Open must fail at
// construction time against an unreachable database, not on the first
// caller's first query.
func TestOpen_BadDSNFailsFast(t *testing.T) {
	_, err := pgpool.Open("postgres://baduser:badpass@127.0.0.1:1/nonexistent?sslmode=disable", 0)
	if err == nil {
		t.Fatal("expected an error opening a pool against an unreachable database")
	}
}

// TestOpen_DefaultsMaxOpenConnsWhenUnset proves Open succeeds (and applies
// the documented default) against a real database when maxOpenConns is
// left at its zero value -- the shape every existing caller in
// cmd/wardline/main.go uses when config.AuditConfig.PostgresMaxOpenConns
// is unset.
func TestOpen_DefaultsMaxOpenConnsWhenUnset(t *testing.T) {
	dsn := os.Getenv("WARDLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("WARDLINE_TEST_POSTGRES_DSN not set, skipping real-Postgres integration test")
	}
	db, err := pgpool.Open(dsn, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if got := db.Stats().MaxOpenConnections; got != 25 {
		t.Errorf("MaxOpenConnections = %d, want default 25", got)
	}
}
