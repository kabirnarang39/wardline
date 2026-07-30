package domain

import "strings"

// Group is a SCIM-provisioned group, mapped from a SCIM 2.0 Group
// resource's displayName and members. Members holds each member's User
// ID (not UserName) per the SCIM spec's own member-reference shape.
type Group struct {
	ID          string
	DisplayName string
	Members     []string
}

// ParseGroupName parses Wardline's group-naming convention that carries
// tenant and role: "wardline:tenant-<tenant>:role-<role>" (a tenant-scoped
// RoleBinding) or "wardline:role-<role>" (a global ClusterRoleBinding, no
// tenant segment -- mirrors rbac.yaml's own no-tenant-means-global
// convention). ok is false for any name that doesn't match either shape
// -- an IdP's own unrelated groups (not everything an IdP provisions is
// meant for Wardline) must be silently ignored, not treated as an error.
func ParseGroupName(name string) (tenantName, role string, isGlobal, ok bool) {
	const prefix = "wardline:"
	if !strings.HasPrefix(name, prefix) {
		return "", "", false, false
	}
	rest := strings.TrimPrefix(name, prefix)

	if strings.HasPrefix(rest, "role-") {
		role = strings.TrimPrefix(rest, "role-")
		if role == "" {
			return "", "", false, false
		}
		return "", role, true, true
	}

	const tenantPrefix = "tenant-"
	if !strings.HasPrefix(rest, tenantPrefix) {
		return "", "", false, false
	}
	rest = strings.TrimPrefix(rest, tenantPrefix)
	parts := strings.SplitN(rest, ":role-", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false, false
	}
	return parts[0], parts[1], false, true
}
