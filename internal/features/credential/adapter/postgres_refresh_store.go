package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

const createRefreshTokensTableSQL = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token TEXT PRIMARY KEY,
	identity_key TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
)`

const issueRefreshTokenSQL = `
INSERT INTO refresh_tokens (token, identity_key, expires_at)
VALUES ($1, $2, $3)`

// redeemRefreshTokenSQL atomically deletes and returns the row in one
// round trip -- Postgres's DELETE ... RETURNING is exactly the
// find-and-single-use-consume primitive this needs, with no
// read-then-delete race window a two-statement version would have.
const redeemRefreshTokenSQL = `
DELETE FROM refresh_tokens WHERE token = $1 RETURNING identity_key, expires_at`

// revokeAllForIdentitySQL deletes every refresh token whose identity_key
// matches either the tenant-scoped key or the bare-identity/wildcard
// key -- mirrors selectRevocationSQL's two-key check in
// postgres_revoker.go, adapted to a DELETE.
const revokeAllForIdentitySQL = `
DELETE FROM refresh_tokens WHERE identity_key = ANY($1)`

// PostgresRefreshStore is a credential/domain.RefreshStore backed by a
// real Postgres database -- the HA-safe alternative to
// InMemoryRefreshStore, wired in when both credential_issuance and
// postgres_storage are on, mirroring PostgresRevoker's
// connection-pool/idempotent-table/timeout pattern exactly. identity_key
// reuses postgresSafeKey (postgres_revoker.go, same package) verbatim --
// the identical (tenant, identity) collision reasoning applies here.
type PostgresRefreshStore struct {
	db *sql.DB
}

// NewPostgresRefreshStore opens a connection pool to dsn, creates the
// refresh_tokens table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first Issue/Redeem call.
func NewPostgresRefreshStore(dsn string) (*PostgresRefreshStore, error) {
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
	if _, err := db.ExecContext(createCtx, createRefreshTokensTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create refresh_tokens table: %w", err)
	}

	return &PostgresRefreshStore{db: db}, nil
}

func (s *PostgresRefreshStore) Issue(token, identity, tenantName string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()
	key := identity
	if tenantName != "" {
		key = postgresSafeKey(tenantName, identity)
	}
	if _, err := s.db.ExecContext(ctx, issueRefreshTokenSQL, token, key, expiresAt); err != nil {
		return fmt.Errorf("issue refresh token for %q (tenant %q): %w", identity, tenantName, err)
	}
	return nil
}

// Redeem is single-use by construction: DELETE ... RETURNING removes
// the row atomically, so a concurrent second Redeem of the same token
// (from any replica, since this is the shared database) gets
// sql.ErrNoRows, indistinguishable from "never existed" -- exactly the
// non-enumerable failure this store's callers want.
func (s *PostgresRefreshStore) Redeem(token string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()

	var identityKey string
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx, redeemRefreshTokenSQL, token).Scan(&identityKey, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", domain.ErrRefreshTokenInvalid
		}
		return "", "", fmt.Errorf("redeem refresh token: %w", err)
	}
	if time.Now().After(expiresAt) {
		return "", "", domain.ErrRefreshTokenInvalid
	}
	identity, tenantName := splitIdentityKey(identityKey)
	return identity, tenantName, nil
}

func (s *PostgresRefreshStore) RevokeAllForIdentity(tenantName, identity string) error {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()

	keys := []string{identity}
	if tenantName != "" {
		keys = []string{postgresSafeKey(tenantName, identity), identity}
	}
	if _, err := s.db.ExecContext(ctx, revokeAllForIdentitySQL, keys); err != nil {
		return fmt.Errorf("revoke refresh tokens for %q (tenant %q): %w", identity, tenantName, err)
	}
	return nil
}

func (s *PostgresRefreshStore) Close() error {
	return s.db.Close()
}

// splitIdentityKey inverts postgresSafeKey (postgres_revoker.go): a key
// with no length-prefix colon-delimiter pattern at all is a bare
// identity (wildcard revoke, tenantName == "" at Issue time) --
// returned with tenantName == "". A length-prefixed key
// "<len>:<tenant>:<identity>" is split at exactly the byte offset the
// prefix names, which is what makes the length-prefixed scheme safe
// against tenant/identity strings containing colons themselves (see
// postgresSafeKey's doc comment for the full collision-avoidance
// reasoning) -- do not attempt to parse this with strings.SplitN(key,
// ":", 3), which breaks the instant either string contains a colon.
func splitIdentityKey(key string) (identity, tenantName string) {
	firstColon := strings.IndexByte(key, ':')
	if firstColon < 0 {
		return key, ""
	}
	prefixLen, err := strconv.Atoi(key[:firstColon])
	if err != nil {
		// Not actually a length-prefixed key (e.g. a bare identity that
		// happens to start with digits followed by a colon) -- treat the
		// whole string as a bare identity, the safe fallback.
		return key, ""
	}
	rest := key[firstColon+1:]
	if len(rest) < prefixLen+1 || rest[prefixLen] != ':' {
		return key, "" // malformed; fail safe to bare-identity interpretation
	}
	return rest[prefixLen+1:], rest[:prefixLen]
}

var _ domain.RefreshStore = (*PostgresRefreshStore)(nil)
