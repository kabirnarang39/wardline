package domain

// ClusterRoleBinding grants a subject a role globally, across every
// tenant — the Kubernetes ClusterRoleBinding shape.
type ClusterRoleBinding struct {
	Subject  string
	RoleName string
}

// RoleBinding grants a subject a role scoped to one tenant — the
// Kubernetes RoleBinding shape. This cycle, "default" is the only
// tenant that exists (see design doc "Out of scope").
type RoleBinding struct {
	Subject  string
	RoleName string
	Tenant   string
}
