package usecase_test

import (
	"testing"

	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/features/rbac/usecase"
)

type fakeStaticAuthorizer struct {
	allow    bool
	isGlobal bool
}

func (f fakeStaticAuthorizer) Authorize(identity, tenant string, perm rbacdomain.Permission) bool {
	return f.allow
}
func (f fakeStaticAuthorizer) IsGlobal(identity string, perm rbacdomain.Permission) bool {
	return f.isGlobal
}

type fakeBindingSource struct {
	cluster []rbacdomain.ClusterRoleBinding
	scoped  []rbacdomain.RoleBinding
}

func (f fakeBindingSource) Bindings(identity string) ([]rbacdomain.ClusterRoleBinding, []rbacdomain.RoleBinding) {
	return f.cluster, f.scoped
}

func TestCompositeAuthorizer_FallsBackToDynamicBindings(t *testing.T) {
	static := fakeStaticAuthorizer{allow: false, isGlobal: false}
	dynamic := fakeBindingSource{
		scoped: []rbacdomain.RoleBinding{{Subject: "alice", RoleName: "admin", Tenant: "acme"}},
	}
	// admin must grant credential:revoke -- reuse the same built-in role
	// definitions the static authorizer already knows; this fake's
	// composite must check the dynamic binding's role against the SAME
	// role definitions, so wire it with a real *adapter.StaticAuthorizer
	// as the "roles" source in the real implementation (see Step 3) --
	// this test uses a role-lookup fake instead to stay decoupled from
	// adapter package.
	c := usecase.NewCompositeAuthorizer(static, dynamic, func(roleName string, perm rbacdomain.Permission) bool {
		return roleName == "admin" && perm == rbacdomain.PermissionCredentialRevoke
	})

	if !c.Authorize("alice", "acme", rbacdomain.PermissionCredentialRevoke) {
		t.Fatal("alice's SCIM-provisioned RoleBinding should grant credential:revoke in tenant acme")
	}
	if c.Authorize("alice", "widgets-inc", rbacdomain.PermissionCredentialRevoke) {
		t.Fatal("alice's binding is scoped to acme, must not grant in a different tenant")
	}
	if c.IsGlobal("alice", rbacdomain.PermissionCredentialRevoke) {
		t.Fatal("alice only has a tenant-scoped dynamic binding, not global")
	}
}
