package adapter

import (
	"context"
	"fmt"
	"log/slog"

	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	scimdomain "github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

// bindingStoreTimeout bounds every Postgres operation this adapter
// performs -- same rationale and same value as
// credential/adapter.PostgresRevoker's revokerTimeout: SetGroupMembers/
// RemoveGroup/Bindings all sit on request paths (SCIM group provisioning
// and RBAC authorization checks respectively), so a blackholed connection
// must degrade to a bounded failure, not hang the caller.
const bindingStoreTimeout = 5 * time.Second

const createSCIMBindingsTableSQL = `
CREATE TABLE IF NOT EXISTS scim_group_bindings (
	group_name TEXT NOT NULL,
	member_username TEXT NOT NULL,
	PRIMARY KEY (group_name, member_username)
)`

// createSCIMBindingsMemberIndexSQL backs Bindings' "WHERE member_username
// = $1" lookup -- the table's only other index is the (group_name,
// member_username) primary key, which doesn't help a query keyed on
// member_username alone. Additive and idempotent, safe to run against an
// existing table every time this adapter starts up.
const createSCIMBindingsMemberIndexSQL = `
CREATE INDEX IF NOT EXISTS scim_group_bindings_member_username_idx
ON scim_group_bindings (member_username)`

// PostgresBindingStore is a Postgres-backed alternative to
// scimusecase.BindingStore's in-memory map -- same public shape
// (SetGroupMembers/RemoveGroup/Bindings), swapped in only at the main.go
// wiring site when features.postgres_storage and scim.persist_postgres
// are both on (mirrors credential/adapter.PostgresRevoker's identical
// dependency-gating pattern). Unlike the in-memory BindingStore, every
// replica connects to the same shared table, so a binding provisioned
// through one replica is seen by every other replica on its next
// Bindings call, and survives a restart.
type PostgresBindingStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresBindingStore creates the scim_group_bindings table and its
// member_username index on db if they don't already exist. db is expected
// already open and pinged -- see pgpool.Open, called once in
// cmd/wardline/main.go and shared across every Postgres-backed feature -- a
// bad db fails here, at construction time, not on the first provisioning
// call. logger is optional (nil is valid, same "logger may be nil"
// convention PostgresRevoker uses) and is used to surface
// SetGroupMembers/RemoveGroup write failures that would otherwise vanish
// silently -- see warn.
func NewPostgresBindingStore(db *sql.DB, logger *slog.Logger) (*PostgresBindingStore, error) {
	createCtx, createCancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createSCIMBindingsTableSQL); err != nil {
		return nil, fmt.Errorf("create scim_group_bindings table: %w", err)
	}
	if _, err := db.ExecContext(createCtx, createSCIMBindingsMemberIndexSQL); err != nil {
		return nil, fmt.Errorf("create scim_group_bindings member_username index: %w", err)
	}

	return &PostgresBindingStore{db: db, logger: logger}, nil
}

// warn logs a write failure at Warn level if a logger was wired in --
// nil-safe, same convention as PostgresRevoker.logger. SetGroupMembers
// and RemoveGroup have no caller-visible error return (matching the
// in-memory BindingStore's error-free signature), so without this a
// failed write vanishes completely -- an operator investigating "why
// didn't this SCIM group's RBAC binding take effect" needs to be able to
// find it in the logs.
func (p *PostgresBindingStore) warn(op, groupName string, err error) {
	if p.logger == nil {
		return
	}
	p.logger.Warn("scim binding store write failed", "op", op, "group_name", groupName, "error", err)
}

// SetGroupMembers implements the same replace-membership semantics as
// scimusecase.BindingStore.SetGroupMembers: groupName's member list is
// replaced wholesale (matching a SCIM Group PUT/PATCH), and a groupName
// that doesn't match Wardline's naming convention is silently ignored.
func (p *PostgresBindingStore) SetGroupMembers(groupName string, memberUserNames []string) {
	if _, _, _, ok := scimdomain.ParseGroupName(groupName); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer cancel()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		p.warn("begin transaction", groupName, err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_bindings WHERE group_name = $1`, groupName); err != nil {
		p.warn("delete existing bindings", groupName, err)
		return
	}
	for _, member := range memberUserNames {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scim_group_bindings (group_name, member_username) VALUES ($1, $2)`, groupName, member); err != nil {
			p.warn("insert binding", groupName, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		p.warn("commit", groupName, err)
	}
}

// RemoveGroup revokes every binding groupName granted.
func (p *PostgresBindingStore) RemoveGroup(groupName string) {
	ctx, cancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer cancel()
	if _, err := p.db.ExecContext(ctx, `DELETE FROM scim_group_bindings WHERE group_name = $1`, groupName); err != nil {
		p.warn("remove group", groupName, err)
	}
}

// Bindings returns every ClusterRoleBinding/RoleBinding identity
// currently holds via SCIM group membership, read from the shared table.
// A query error fails open (returns no bindings) rather than propagating,
// matching the in-memory BindingStore's error-free signature.
func (p *PostgresBindingStore) Bindings(identity string) (cluster []rbacdomain.ClusterRoleBinding, scoped []rbacdomain.RoleBinding) {
	ctx, cancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer cancel()

	rows, err := p.db.QueryContext(ctx, `SELECT group_name FROM scim_group_bindings WHERE member_username = $1`, identity)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var groupName string
		if err := rows.Scan(&groupName); err != nil {
			continue
		}
		tenantName, role, isGlobal, ok := scimdomain.ParseGroupName(groupName)
		if !ok {
			continue
		}
		if isGlobal {
			cluster = append(cluster, rbacdomain.ClusterRoleBinding{Subject: identity, RoleName: role})
		} else {
			scoped = append(scoped, rbacdomain.RoleBinding{Subject: identity, RoleName: role, Tenant: tenantName})
		}
	}
	// rows.Next() returns false both on genuine exhaustion AND when the
	// loop was cut short by a scan/connection error mid-iteration --
	// checking rows.Err() after the loop is the only way to tell those
	// apart. Treat a real error the same as the initial QueryContext
	// error above: fail open by discarding whatever partial results were
	// scanned, rather than silently returning an authorization decision
	// based on an incomplete read.
	if err := rows.Err(); err != nil {
		return nil, nil
	}
	return cluster, scoped
}
