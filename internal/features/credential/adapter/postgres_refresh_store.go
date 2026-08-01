package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kabirnarang39/wardline/internal/features/credential/domain"
)

// createRefreshTokensTableSQL keeps tenant and identity in two separate
// columns rather than one encoded key (postgresSafeKey's
// "<len>:<tenant>:<identity>" shape, as revoked_identities uses). Two
// columns are what make the wildcard revoke below expressible at all:
// "every tenant's rows for this identity" is a query on one column,
// which no single-encoded-key column can answer without a prefix/suffix
// match that would reintroduce exactly the tenant/identity boundary
// ambiguity the length prefix exists to avoid. tenant stores "" for the
// no-tenant case -- the same wildcard convention domain.Revoker uses,
// made an explicit column value instead of a key shape.
const createRefreshTokensTableSQL = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token TEXT PRIMARY KEY,
	tenant TEXT NOT NULL,
	identity TEXT NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
)`

// issueRefreshTokenSQL stores tenant and identity verbatim -- no
// encoding step, so no decoding step on redeem either.
const issueRefreshTokenSQL = `
INSERT INTO refresh_tokens (token, tenant, identity, expires_at)
VALUES ($1, $2, $3, $4)`

// redeemRefreshTokenSQL atomically deletes and returns the row in one
// round trip -- Postgres's DELETE ... RETURNING is exactly the
// find-and-single-use-consume primitive this needs, with no
// read-then-delete race window a two-statement version would have.
const redeemRefreshTokenSQL = `
DELETE FROM refresh_tokens WHERE token = $1 RETURNING tenant, identity, expires_at`

// revokeAllForIdentityScopedSQL deletes only the named tenant's refresh
// tokens for this identity, leaving other tenants' rows for the same
// identity string alone (distinct principals that merely share a name).
const revokeAllForIdentityScopedSQL = `
DELETE FROM refresh_tokens WHERE identity = $1 AND tenant = $2`

// revokeAllForIdentityWildcardSQL deliberately has NO tenant predicate:
// tenantName == "" means "revoke this identity everywhere", so filtering
// on tenant at all -- including an ANY($1) set-membership check against
// {tenant-scoped key, bare key} the way selectRevocationSQL does -- is
// wrong here. That set-membership shape is right for the Revoker, whose
// query looks up one row that could be stored under either shape for a
// SPECIFIC tenant; applied to a wildcard DELETE it silently matched only
// rows stored with no tenant, so tenant-scoped rows survived a revoke.
// That was a real, reachable bug: under bootstrap_source: oidc every
// revoke is a wildcard revoke (identityTenantLookup always fails) while
// every oidc-issued token is stored tenant-scoped, so revoked identities
// kept a live refresh token and could mint access tokens forever. Keep
// these two queries structurally different.
const revokeAllForIdentityWildcardSQL = `
DELETE FROM refresh_tokens WHERE identity = $1`

// PostgresRefreshStore is a credential/domain.RefreshStore backed by a
// real Postgres database -- the HA-safe alternative to
// InMemoryRefreshStore, wired in when both credential_issuance and
// postgres_storage are on, mirroring PostgresRevoker's
// connection-pool/idempotent-table/timeout pattern exactly. Unlike
// PostgresRevoker it stores tenant and identity as two plain columns
// rather than one postgresSafeKey-encoded key -- see
// createRefreshTokensTableSQL for why.
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
	if _, err := s.db.ExecContext(ctx, issueRefreshTokenSQL, token, tenantName, identity, expiresAt); err != nil {
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

	var tenantName, identity string
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx, redeemRefreshTokenSQL, token).Scan(&tenantName, &identity, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", domain.ErrRefreshTokenInvalid
		}
		return "", "", fmt.Errorf("redeem refresh token: %w", err)
	}
	if time.Now().After(expiresAt) {
		return "", "", domain.ErrRefreshTokenInvalid
	}
	return identity, tenantName, nil
}

// RevokeAllForIdentity matches InMemoryRefreshStore's semantics exactly:
// tenantName == "" is a wildcard that deletes this identity's tokens in
// EVERY tenant, anything else deletes only that tenant's. The two cases
// need structurally different SQL, not one parameterised query -- see
// revokeAllForIdentityWildcardSQL.
func (s *PostgresRefreshStore) RevokeAllForIdentity(tenantName, identity string) error {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()

	var err error
	if tenantName == "" {
		_, err = s.db.ExecContext(ctx, revokeAllForIdentityWildcardSQL, identity)
	} else {
		_, err = s.db.ExecContext(ctx, revokeAllForIdentityScopedSQL, identity, tenantName)
	}
	if err != nil {
		return fmt.Errorf("revoke refresh tokens for %q (tenant %q): %w", identity, tenantName, err)
	}
	return nil
}

func (s *PostgresRefreshStore) Close() error {
	return s.db.Close()
}

var _ domain.RefreshStore = (*PostgresRefreshStore)(nil)
