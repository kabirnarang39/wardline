package usecase

import (
	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

// dynamicBindingSource is the subset of scimusecase.BindingStore's
// behavior CompositeAuthorizer depends on -- a narrow local interface so
// this package doesn't import scim/usecase by name (Open/Closed: any
// future dynamic-binding source can plug in here).
type dynamicBindingSource interface {
	Bindings(identity string) (cluster []domain.ClusterRoleBinding, scoped []domain.RoleBinding)
}

// roleHasPermission looks up whether roleName grants perm -- CompositeAuthorizer
// needs this to evaluate a *dynamic* binding's role, since domain.Authorizer's
// Authorize/IsGlobal only answer for bindings the implementation already knows
// about internally, not a role name handed in externally.
type roleHasPermission func(roleName string, perm domain.Permission) bool

// CompositeAuthorizer checks a static (file-loaded) domain.Authorizer
// first, then falls back to a dynamic (SCIM-provisioned) binding source
// -- StaticAuthorizer itself is never modified (Open/Closed), matching
// how the Cedar/OPA policy backends were added as new implementations
// rather than edits to the YAML matcher.
type CompositeAuthorizer struct {
	static             domain.Authorizer
	dynamic            dynamicBindingSource
	dynamicRoleHasPerm roleHasPermission
}

func NewCompositeAuthorizer(static domain.Authorizer, dynamic dynamicBindingSource, dynamicRoleHasPerm roleHasPermission) *CompositeAuthorizer {
	return &CompositeAuthorizer{static: static, dynamic: dynamic, dynamicRoleHasPerm: dynamicRoleHasPerm}
}

func (c *CompositeAuthorizer) Authorize(identity, tenant string, perm domain.Permission) bool {
	if c.static.Authorize(identity, tenant, perm) {
		return true
	}
	cluster, scoped := c.dynamic.Bindings(identity)
	for _, b := range cluster {
		if c.dynamicRoleHasPerm(b.RoleName, perm) {
			return true
		}
	}
	for _, b := range scoped {
		if b.Tenant == tenant && c.dynamicRoleHasPerm(b.RoleName, perm) {
			return true
		}
	}
	return false
}

func (c *CompositeAuthorizer) IsGlobal(identity string, perm domain.Permission) bool {
	if c.static.IsGlobal(identity, perm) {
		return true
	}
	cluster, _ := c.dynamic.Bindings(identity)
	for _, b := range cluster {
		if c.dynamicRoleHasPerm(b.RoleName, perm) {
			return true
		}
	}
	return false
}
