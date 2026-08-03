package adapter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/rbac/adapter"
	"github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

func writeRBACFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rbac.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAuthorizer_BuiltinRolesAlwaysAvailable(t *testing.T) {
	path := writeRBACFile(t, `
bindings:
  - subject: alice
    role: admin
  - subject: bob
    role: viewer
`)
	a, err := adapter.LoadAuthorizer(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.Authorize("alice", "default", domain.PermissionDashboardView) {
		t.Error("expected alice (admin, cluster-scoped) to have dashboard:view")
	}
	if !a.Authorize("alice", "default", domain.PermissionCredentialRevoke) {
		t.Error("expected alice (admin, cluster-scoped) to have credential:revoke")
	}
	if !a.Authorize("alice", "default", domain.PermissionConfigEdit) {
		t.Error("expected alice (admin, cluster-scoped) to have config:edit")
	}
	if !a.Authorize("bob", "default", domain.PermissionDashboardView) {
		t.Error("expected bob (viewer, cluster-scoped) to have dashboard:view")
	}
	if a.Authorize("bob", "default", domain.PermissionCredentialRevoke) {
		t.Error("expected bob (viewer) to NOT have credential:revoke")
	}
	if a.Authorize("bob", "default", domain.PermissionConfigEdit) {
		t.Error("expected bob (viewer) to NOT have config:edit")
	}
}

func TestLoadAuthorizer_UnboundIdentityHasNoPermissions(t *testing.T) {
	path := writeRBACFile(t, `bindings: []`)
	a, err := adapter.LoadAuthorizer(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Authorize("nobody", "default", domain.PermissionDashboardView) {
		t.Error("expected an unbound identity to have no permissions")
	}
}

func TestLoadAuthorizer_CustomRoleMerged(t *testing.T) {
	path := writeRBACFile(t, `
roles:
  - name: auditor
    permissions: ["dashboard:view"]
bindings:
  - subject: carol
    role: auditor
`)
	a, err := adapter.LoadAuthorizer(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.Authorize("carol", "default", domain.PermissionDashboardView) {
		t.Error("expected carol (custom auditor role) to have dashboard:view")
	}
	if a.Authorize("carol", "default", domain.PermissionCredentialRevoke) {
		t.Error("expected carol (auditor, no revoke permission) to NOT have credential:revoke")
	}
}

func TestLoadAuthorizer_CustomRoleReusingBuiltinNameErrors(t *testing.T) {
	path := writeRBACFile(t, `
roles:
  - name: admin
    permissions: ["dashboard:view"]
bindings: []
`)
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error when a custom role reuses a built-in role name")
	}
}

func TestLoadAuthorizer_BindingReferencingUndefinedRoleErrors(t *testing.T) {
	path := writeRBACFile(t, `
bindings:
  - subject: alice
    role: does-not-exist
`)
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error for a binding referencing an undefined role")
	}
}

func TestLoadAuthorizer_RoleBindingScopedToTenant(t *testing.T) {
	path := writeRBACFile(t, `
bindings:
  - subject: dave
    role: viewer
    tenant: team-payments
`)
	a, err := adapter.LoadAuthorizer(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.Authorize("dave", "team-payments", domain.PermissionDashboardView) {
		t.Error("expected dave to have dashboard:view within his bound tenant")
	}
	if a.Authorize("dave", "default", domain.PermissionDashboardView) {
		t.Error("expected dave's tenant-scoped RoleBinding to NOT grant access to a different tenant")
	}
}

func TestLoadAuthorizer_MissingFileErrors(t *testing.T) {
	_, err := adapter.LoadAuthorizer(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadAuthorizer_MalformedYAMLErrors(t *testing.T) {
	path := writeRBACFile(t, "not: [valid yaml")
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
}

func TestLoadAuthorizer_BindingMissingSubjectOrRoleErrors(t *testing.T) {
	path := writeRBACFile(t, `
bindings:
  - subject: ""
    role: viewer
`)
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error for a binding missing a subject")
	}
}

func TestLoadAuthorizer_DuplicateCustomRoleNameErrors(t *testing.T) {
	path := writeRBACFile(t, `
roles:
  - name: auditor
    permissions: ["dashboard:view"]
  - name: auditor
    permissions: ["credential:revoke"]
bindings: []
`)
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error when a custom role is defined more than once")
	}
}

func TestLoadAuthorizer_UnknownPermissionErrors(t *testing.T) {
	path := writeRBACFile(t, `
roles:
  - name: auditor
    permissions: ["dashboard:view", "dashbord:view"]
bindings: []
`)
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error for an unknown permission string")
	}
}

// TestLoadAuthorizer_UnknownBindingFieldErrors covers the strict-decode
// regression this fix closes: a typo'd binding key (e.g. "tenatt" instead
// of "tenant") must fail to load, not silently zero-value Tenant and
// route the binding into clusterRoleBindings (global scope) instead of
// the tenant-scoped RoleBinding the operator intended.
func TestLoadAuthorizer_UnknownBindingFieldErrors(t *testing.T) {
	path := writeRBACFile(t, `
bindings:
  - subject: alice
    role: admin
    tenatt: default
`)
	_, err := adapter.LoadAuthorizer(path)
	if err == nil {
		t.Fatal("expected an error for a binding with an unknown field (tenant typo)")
	}
}

// TestLoadAuthorizer_EmptyFileLoadsSuccessfully proves the switch to a
// strict decoder didn't break the "empty rbac.yaml is valid" case — an
// empty file decodes to io.EOF, which LoadAuthorizer must treat as an
// empty rbacFile, not an error.
func TestLoadAuthorizer_EmptyFileLoadsSuccessfully(t *testing.T) {
	path := writeRBACFile(t, "")
	a, err := adapter.LoadAuthorizer(path)
	if err != nil {
		t.Fatalf("unexpected error loading an empty rbac.yaml: %v", err)
	}
	if a.Authorize("nobody", "default", domain.PermissionDashboardView) {
		t.Error("expected zero bindings (and thus no granted permissions) from an empty rbac.yaml")
	}
}

func TestIsGlobal_TrueOnlyForClusterRoleBinding(t *testing.T) {
	path := writeRBACFile(t, `
bindings:
  - subject: alice
    role: admin
  - subject: bob
    role: admin
    tenant: acme
`)
	a, err := adapter.LoadAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsGlobal("alice", domain.PermissionCredentialRevoke) {
		t.Fatal("alice has a ClusterRoleBinding, want IsGlobal true")
	}
	if a.IsGlobal("bob", domain.PermissionCredentialRevoke) {
		t.Fatal("bob only has a tenant-scoped RoleBinding, want IsGlobal false")
	}
}
