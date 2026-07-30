package domain

// Authorizer decides whether identity holds perm within tenant, via
// whatever ClusterRoleBindings/RoleBindings it was constructed from.
type Authorizer interface {
	Authorize(identity, tenant string, perm Permission) bool
	// IsGlobal reports whether identity holds perm via a ClusterRoleBinding
	// (grants across every tenant), as opposed to only a tenant-scoped
	// RoleBinding.
	IsGlobal(identity string, perm Permission) bool
}
