package usecase

import (
	"sync"

	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	scimdomain "github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

type groupGrant struct {
	tenant   string
	role     string
	isGlobal bool
}

// BindingStore holds SCIM-provisioned group->role/tenant grants and
// derives per-identity RoleBindings/ClusterRoleBindings from current
// group membership -- in-memory only this task; Task 15 adds an
// optional Postgres-backed alternative behind the same shape.
type BindingStore struct {
	mu sync.Mutex
	// groupMembers maps a Wardline-recognized group name to its current
	// member identity names.
	groupMembers map[string][]string
	// groupGrants maps a Wardline-recognized group name to the
	// tenant/role/scope it was parsed into -- computed once per
	// SetGroupMembers call rather than re-parsed on every Bindings call.
	groupGrants map[string]groupGrant
}

func NewBindingStore() *BindingStore {
	return &BindingStore{
		groupMembers: make(map[string][]string),
		groupGrants:  make(map[string]groupGrant),
	}
}

// SetGroupMembers replaces groupName's member list wholesale (matching a
// SCIM Group PUT/PATCH's replace-membership semantics). A groupName that
// doesn't match Wardline's naming convention (domain.ParseGroupName
// returns ok=false) is silently ignored -- an IdP's other, non-Wardline
// groups must not error.
func (s *BindingStore) SetGroupMembers(groupName string, memberUserNames []string) {
	tenantName, role, isGlobal, ok := scimdomain.ParseGroupName(groupName)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupMembers[groupName] = append([]string{}, memberUserNames...)
	s.groupGrants[groupName] = groupGrant{tenant: tenantName, role: role, isGlobal: isGlobal}
}

// RemoveGroup revokes every binding groupName granted.
func (s *BindingStore) RemoveGroup(groupName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groupMembers, groupName)
	delete(s.groupGrants, groupName)
}

// Bindings returns every ClusterRoleBinding/RoleBinding identity
// currently holds via SCIM group membership.
func (s *BindingStore) Bindings(identity string) (cluster []rbacdomain.ClusterRoleBinding, scoped []rbacdomain.RoleBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for groupName, members := range s.groupMembers {
		if !containsString(members, identity) {
			continue
		}
		grant := s.groupGrants[groupName]
		if grant.isGlobal {
			cluster = append(cluster, rbacdomain.ClusterRoleBinding{Subject: identity, RoleName: grant.role})
		} else {
			scoped = append(scoped, rbacdomain.RoleBinding{Subject: identity, RoleName: grant.role, Tenant: grant.tenant})
		}
	}
	return cluster, scoped
}

func containsString(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
