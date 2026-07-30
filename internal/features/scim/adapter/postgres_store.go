package adapter

import (
	"context"
	"fmt"

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
	db *sql.DB
}

// NewPostgresBindingStore opens a connection pool to dsn, creates the
// scim_group_bindings table if it doesn't already exist, and pings the
// connection -- a bad DSN or unreachable database fails here, at
// construction time, not on the first provisioning call. Mirrors
// PostgresRevoker's connection-pool and idempotent-table pattern exactly.
func NewPostgresBindingStore(dsn string) (*PostgresBindingStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createCtx, createCancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer createCancel()
	if _, err := db.ExecContext(createCtx, createSCIMBindingsTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create scim_group_bindings table: %w", err)
	}

	return &PostgresBindingStore{db: db}, nil
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
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_bindings WHERE group_name = $1`, groupName); err != nil {
		return
	}
	for _, member := range memberUserNames {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scim_group_bindings (group_name, member_username) VALUES ($1, $2)`, groupName, member); err != nil {
			return
		}
	}
	_ = tx.Commit()
}

// RemoveGroup revokes every binding groupName granted.
func (p *PostgresBindingStore) RemoveGroup(groupName string) {
	ctx, cancel := context.WithTimeout(context.Background(), bindingStoreTimeout)
	defer cancel()
	_, _ = p.db.ExecContext(ctx, `DELETE FROM scim_group_bindings WHERE group_name = $1`, groupName)
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
	return cluster, scoped
}

// Close releases the underlying connection pool, draining in-flight
// connections. Called during Wardline's graceful shutdown.
func (p *PostgresBindingStore) Close() error {
	return p.db.Close()
}
