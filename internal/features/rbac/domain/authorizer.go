package domain

// Authorizer decides whether identity holds perm within tenant, via
// whatever ClusterRoleBindings/RoleBindings it was constructed from.
type Authorizer interface {
	Authorize(identity, tenant string, perm Permission) bool
}
