package adapter

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

// builtinRoles are always available, regardless of what an operator's
// rbac.yaml defines — the only two permissions anything in the codebase
// checks today. A custom role may not reuse either name.
var builtinRoles = map[string]domain.Role{
	"viewer": {Name: "viewer", Permissions: []domain.Permission{domain.PermissionDashboardView}},
	"admin": {Name: "admin", Permissions: []domain.Permission{
		domain.PermissionDashboardView,
		domain.PermissionCredentialRevoke,
	}},
}

type roleConfig struct {
	Name        string   `yaml:"name"`
	Permissions []string `yaml:"permissions"`
}

type bindingConfig struct {
	Subject string `yaml:"subject"`
	Role    string `yaml:"role"`
	Tenant  string `yaml:"tenant"` // empty -> ClusterRoleBinding (global)
}

type rbacFile struct {
	Roles    []roleConfig    `yaml:"roles"`
	Bindings []bindingConfig `yaml:"bindings"`
}

// StaticAuthorizer is a domain.Authorizer backed by roles and bindings
// loaded once from rbac.yaml at construction — same fail-fast-at-startup
// posture as policy.LoadFile and credential's LoadBootstrapper. Bindings
// are held as slices and scanned linearly on every Authorize call: this
// is an admin-surface, low-frequency path (dashboard views, credential
// revokes), not the hot proxy path, so a map index would be premature.
type StaticAuthorizer struct {
	roles               map[string]domain.Role
	clusterRoleBindings []domain.ClusterRoleBinding
	roleBindings        []domain.RoleBinding
}

func LoadAuthorizer(path string) (*StaticAuthorizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rbac file %s: %w", path, err)
	}
	var f rbacFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse rbac file %s: %w", path, err)
	}

	roles := make(map[string]domain.Role, len(builtinRoles)+len(f.Roles))
	for name, r := range builtinRoles {
		roles[name] = r
	}
	knownPermissions := map[string]bool{
		"dashboard:view":    true,
		"credential:revoke": true,
	}
	for _, rc := range f.Roles {
		if rc.Name == "" {
			return nil, fmt.Errorf("rbac file %s: a role entry is missing a name", path)
		}
		if _, isBuiltin := builtinRoles[rc.Name]; isBuiltin {
			return nil, fmt.Errorf("rbac file %s: role %q collides with a built-in role name", path, rc.Name)
		}
		if _, isDuplicate := roles[rc.Name]; isDuplicate {
			return nil, fmt.Errorf("rbac file %s: role %q is defined more than once", path, rc.Name)
		}
		perms := make([]domain.Permission, 0, len(rc.Permissions))
		for _, p := range rc.Permissions {
			if !knownPermissions[p] {
				return nil, fmt.Errorf("rbac file %s: role %q has unknown permission %q (want one of: dashboard:view, credential:revoke)", path, rc.Name, p)
			}
			perms = append(perms, domain.Permission(p))
		}
		roles[rc.Name] = domain.Role{Name: rc.Name, Permissions: perms}
	}

	a := &StaticAuthorizer{roles: roles}
	for _, bc := range f.Bindings {
		if bc.Subject == "" || bc.Role == "" {
			return nil, fmt.Errorf("rbac file %s: every binding must have both subject and role", path)
		}
		if _, ok := roles[bc.Role]; !ok {
			return nil, fmt.Errorf("rbac file %s: binding for %q references undefined role %q", path, bc.Subject, bc.Role)
		}
		if bc.Tenant == "" {
			a.clusterRoleBindings = append(a.clusterRoleBindings, domain.ClusterRoleBinding{Subject: bc.Subject, RoleName: bc.Role})
		} else {
			a.roleBindings = append(a.roleBindings, domain.RoleBinding{Subject: bc.Subject, RoleName: bc.Role, Tenant: bc.Tenant})
		}
	}
	return a, nil
}

func (a *StaticAuthorizer) Authorize(identity, tenant string, perm domain.Permission) bool {
	for _, b := range a.clusterRoleBindings {
		if b.Subject == identity && a.roleHasPermission(b.RoleName, perm) {
			return true
		}
	}
	for _, b := range a.roleBindings {
		if b.Subject == identity && b.Tenant == tenant && a.roleHasPermission(b.RoleName, perm) {
			return true
		}
	}
	return false
}

func (a *StaticAuthorizer) roleHasPermission(roleName string, perm domain.Permission) bool {
	role, ok := a.roles[roleName]
	if !ok {
		return false
	}
	for _, p := range role.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}
