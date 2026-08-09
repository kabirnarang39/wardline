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

// alterRefreshTokensAddFamilySQL and alterRefreshTokensAddConsumedSQL
// migrate a pre-reuse-detection table in place: ADD COLUMN IF NOT EXISTS
// is a no-op on a table that already has them (fresh installs get them
// from a later CREATE run just the same). Existing rows get family=”
// and consumed=false, which Redeem handles safely -- a legacy empty-family
// row that is reused deletes only itself, never a whole family (see
// Redeem). The updated_at index for anomaly baselines has no analogue
// here: refresh_tokens lookups are all by the token primary key.
const alterRefreshTokensAddFamilySQL = `
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family TEXT NOT NULL DEFAULT ''`

const alterRefreshTokensAddConsumedSQL = `
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS consumed BOOLEAN NOT NULL DEFAULT false`

const createRefreshTokensFamilyIndexSQL = `
CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family)`

// issueRefreshTokenSQL stores tenant and identity verbatim -- no
// encoding step, so no decoding step on redeem either. consumed defaults
// to false via the column default.
const issueRefreshTokenSQL = `
INSERT INTO refresh_tokens (token, tenant, identity, family, expires_at)
VALUES ($1, $2, $3, $4, $5)`

// selectRefreshForUpdateSQL locks the row for the duration of the Redeem
// transaction so two concurrent redeems of the same token -- from any
// replica sharing this database -- serialize: the first transitions the
// row, the second sees the already-transitioned state and takes the
// reuse branch, rather than both reading "active" and both succeeding.
const selectRefreshForUpdateSQL = `
SELECT tenant, identity, family, expires_at, consumed FROM refresh_tokens WHERE token = $1 FOR UPDATE`

const markRefreshConsumedSQL = `UPDATE refresh_tokens SET consumed = true WHERE token = $1`

const deleteRefreshTokenSQL = `DELETE FROM refresh_tokens WHERE token = $1`

const deleteRefreshFamilySQL = `DELETE FROM refresh_tokens WHERE family = $1`

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
	for _, stmt := range []string{alterRefreshTokensAddFamilySQL, alterRefreshTokensAddConsumedSQL, createRefreshTokensFamilyIndexSQL} {
		if _, err := db.ExecContext(createCtx, stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate refresh_tokens table: %w", err)
		}
	}

	return &PostgresRefreshStore{db: db}, nil
}

func (s *PostgresRefreshStore) Issue(token, identity, tenantName, family string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, issueRefreshTokenSQL, token, tenantName, identity, family, expiresAt); err != nil {
		return fmt.Errorf("issue refresh token for %q (tenant %q): %w", identity, tenantName, err)
	}
	return nil
}

// Redeem runs the reuse-detecting state machine (see domain.RefreshStore)
// in one transaction, locking the row with SELECT ... FOR UPDATE so
// concurrent redeems of the same token -- from any replica sharing this
// database -- serialize rather than both succeeding. An active token is
// marked consumed (kept, so a replay is detectable); a replay of an
// already-consumed token deletes its whole family and returns
// ErrRefreshTokenReused; an unknown or expired token returns
// ErrRefreshTokenInvalid.
func (s *PostgresRefreshStore) Redeem(token string) (string, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), revokerTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("begin redeem transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	var tenantName, identity, family string
	var expiresAt time.Time
	var consumed bool
	err = tx.QueryRowContext(ctx, selectRefreshForUpdateSQL, token).Scan(&tenantName, &identity, &family, &expiresAt, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", domain.ErrRefreshTokenInvalid
		}
		return "", "", "", fmt.Errorf("redeem refresh token: %w", err)
	}

	if consumed {
		// Reuse of a consumed token: theft signal. Wipe the whole family.
		// A legacy row migrated from before this feature has family='' --
		// there deleting the whole "family" would nuke every other legacy
		// row, so scope the delete to just this token instead.
		delSQL, delArg := deleteRefreshFamilySQL, family
		if family == "" {
			delSQL, delArg = deleteRefreshTokenSQL, token
		}
		if _, err := tx.ExecContext(ctx, delSQL, delArg); err != nil {
			return "", "", "", fmt.Errorf("revoke reused refresh token family: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return "", "", "", fmt.Errorf("commit family revocation: %w", err)
		}
		return "", "", "", domain.ErrRefreshTokenReused
	}

	if time.Now().After(expiresAt) {
		if _, err := tx.ExecContext(ctx, deleteRefreshTokenSQL, token); err != nil {
			return "", "", "", fmt.Errorf("delete expired refresh token: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return "", "", "", fmt.Errorf("commit expired-token delete: %w", err)
		}
		return "", "", "", domain.ErrRefreshTokenInvalid
	}

	if _, err := tx.ExecContext(ctx, markRefreshConsumedSQL, token); err != nil {
		return "", "", "", fmt.Errorf("mark refresh token consumed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", "", "", fmt.Errorf("commit refresh consume: %w", err)
	}
	return identity, tenantName, family, nil
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
