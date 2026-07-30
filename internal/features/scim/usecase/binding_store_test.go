package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/usecase"
)

func TestBindingStore_DerivesBindingsFromGroupMembership(t *testing.T) {
	s := usecase.NewBindingStore()
	s.SetGroupMembers("wardline:tenant-acme:role-admin", []string{"alice", "bob"})
	s.SetGroupMembers("wardline:role-viewer", []string{"alice"})
	s.SetGroupMembers("some-other-idp-group", []string{"alice"}) // must be silently ignored

	cluster, scoped := s.Bindings("alice")
	if len(cluster) != 1 || cluster[0].RoleName != "viewer" {
		t.Fatalf("alice's cluster bindings = %+v, want one ClusterRoleBinding{RoleName: viewer}", cluster)
	}
	if len(scoped) != 1 || scoped[0].RoleName != "admin" || scoped[0].Tenant != "acme" {
		t.Fatalf("alice's scoped bindings = %+v, want one RoleBinding{RoleName: admin, Tenant: acme}", scoped)
	}

	cluster, scoped = s.Bindings("carol") // never provisioned
	if len(cluster) != 0 || len(scoped) != 0 {
		t.Fatalf("carol should have no bindings, got cluster=%+v scoped=%+v", cluster, scoped)
	}
}

func TestBindingStore_RemoveGroup_RevokesMembership(t *testing.T) {
	s := usecase.NewBindingStore()
	s.SetGroupMembers("wardline:role-admin", []string{"alice"})
	s.RemoveGroup("wardline:role-admin")

	cluster, _ := s.Bindings("alice")
	if len(cluster) != 0 {
		t.Fatalf("alice's bindings after group removal = %+v, want none", cluster)
	}
}
