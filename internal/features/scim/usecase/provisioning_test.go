package usecase_test

import (
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/usecase"
)

// TestPatchGroupMembers_DoesNotAliasEarlierGetGroupSnapshot is a
// regression test for a fix-round finding: PatchGroupMembers used to
// filter a group's Members in place, reusing the same backing array a
// prior GetGroup/ListGroups caller may still be holding a reference to
// (domain.Group is copied by value, but its Members slice header still
// points at the map's backing array). That let an unrelated
// PatchGroupMembers call silently mutate a caller's earlier snapshot.
func TestPatchGroupMembers_DoesNotAliasEarlierGetGroupSnapshot(t *testing.T) {
	svc := usecase.NewProvisioningService()
	alice, err := svc.CreateUser("alice", true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := svc.CreateUser("bob", true)
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	g, err := svc.CreateGroup("wardline:role-admin", []string{alice.ID, bob.ID})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Snapshot Members the way an earlier caller (e.g. a concurrent GET
	// request) might have -- via GetGroup, before any PATCH runs.
	snapshot, err := svc.GetGroup(g.ID)
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	snapshotMembers := append([]string(nil), snapshot.Members...) // what the caller expects to keep seeing
	if len(snapshot.Members) != 2 {
		t.Fatalf("expected 2 members in snapshot, got %d", len(snapshot.Members))
	}

	// Removing the *first* member (not the last) is what actually
	// exercises the aliasing bug: the old in-place filter only
	// overwrites a backing-array slot when a later kept element shifts
	// down past an earlier removed one, which only happens here because
	// alice (index 0) is removed while bob (index 1) is kept.
	if err := svc.PatchGroupMembers(g.ID, nil, []string{alice.ID}); err != nil {
		t.Fatalf("patch remove alice: %v", err)
	}

	for i, v := range snapshot.Members {
		if v != snapshotMembers[i] {
			t.Fatalf("snapshot.Members mutated after PatchGroupMembers: got %v, want unchanged %v", snapshot.Members, snapshotMembers)
		}
	}
}

// TestCreateGroup_DedupesMembers is a regression test for a fix-round
// finding: unlike PatchGroupMembers's add path, CreateGroup used to
// store the POST body's member list verbatim, so a duplicate
// {"value":"x"} entry created a duplicate member.
func TestCreateGroup_DedupesMembers(t *testing.T) {
	svc := usecase.NewProvisioningService()
	alice, err := svc.CreateUser("alice", true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}

	g, err := svc.CreateGroup("wardline:role-admin", []string{alice.ID, alice.ID, alice.ID})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	if len(g.Members) != 1 {
		t.Fatalf("expected deduped members, got %v", g.Members)
	}
}

// TestPatchUserActive_False_RevokesDerivedBinding is a C1 regression
// test: PATCH {"op":"replace","path":"active","value":false} is the
// primary offboarding signal from every IdP this feature targets, and
// used to leave the deactivated user's derived RoleBinding in place.
func TestPatchUserActive_False_RevokesDerivedBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	svc.SetBindingStore(store)

	alice, err := svc.CreateUser("alice", true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := svc.CreateGroup("wardline:tenant-acme:role-admin", []string{alice.ID}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if _, scoped := store.Bindings("alice"); len(scoped) != 1 {
		t.Fatalf("expected alice to hold a scoped binding before deactivation, got %+v", scoped)
	}

	if err := svc.PatchUserActive(alice.ID, false); err != nil {
		t.Fatalf("deactivate alice: %v", err)
	}

	if _, scoped := store.Bindings("alice"); len(scoped) != 0 {
		t.Fatalf("expected alice's scoped binding revoked after deactivation, got %+v", scoped)
	}
}

// TestDeleteUser_RevokesDerivedBinding is a C1 regression test: deleting
// a SCIM user used to leave a stale BindingStore entry keyed on their
// username, surviving until some other group happened to be mutated.
func TestDeleteUser_RevokesDerivedBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	svc.SetBindingStore(store)

	alice, err := svc.CreateUser("alice", true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := svc.CreateGroup("wardline:tenant-acme:role-admin", []string{alice.ID}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if _, scoped := store.Bindings("alice"); len(scoped) != 1 {
		t.Fatalf("expected alice to hold a scoped binding before deletion, got %+v", scoped)
	}

	if err := svc.DeleteUser(alice.ID); err != nil {
		t.Fatalf("delete alice: %v", err)
	}

	if _, scoped := store.Bindings("alice"); len(scoped) != 0 {
		t.Fatalf("expected alice's scoped binding revoked after deletion, got %+v", scoped)
	}
}

// TestSyncBinding_InactiveMemberNeverGrantedBinding is a C1 regression
// test covering the third probe finding: an inactive member must never
// be granted a binding in the first place, including via a global
// (ClusterRoleBinding) group.
func TestSyncBinding_InactiveMemberNeverGrantedBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	svc.SetBindingStore(store)

	mallory, err := svc.CreateUser("mallory", false) // inactive from creation
	if err != nil {
		t.Fatalf("create mallory: %v", err)
	}
	if _, err := svc.CreateGroup("wardline:role-admin", []string{mallory.ID}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	cluster, scoped := store.Bindings("mallory")
	if len(cluster) != 0 || len(scoped) != 0 {
		t.Fatalf("expected inactive mallory granted no binding, got cluster=%+v scoped=%+v", cluster, scoped)
	}
}

// TestCreateUser_UserNameReusableAfterDelete is the regression test for
// the O(1) userNameToID index (bench/scimload's load-testing surfaced
// CreateUser/CreateGroup's old O(n)-scan-under-a-single-mutex cost
// visibly degrading with total resource count -- see
// docs-site/content/advanced/benchmarks.md). The obvious bug an index
// like this can introduce is exactly what this test guards: DeleteUser
// forgetting to clean up its index entry, which would make a deleted
// userName permanently unreusable ("conflict" forever) even though the
// old linear-scan version would have allowed it back after the delete.
func TestCreateUser_UserNameReusableAfterDelete(t *testing.T) {
	svc := usecase.NewProvisioningService()
	first, err := svc.CreateUser("alice", true)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if err := svc.DeleteUser(first.ID); err != nil {
		t.Fatalf("delete alice: %v", err)
	}
	second, err := svc.CreateUser("alice", true)
	if err != nil {
		t.Fatalf("expected \"alice\" to be reusable after delete, got: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("expected a fresh ID for the recreated user, got the deleted one's ID")
	}
	if _, ok := svc.GetUserByName("alice"); !ok {
		t.Fatal("expected GetUserByName to find the recreated user")
	}
}

// TestCreateGroup_DisplayNameReusableAfterDelete is CreateUser's
// TestCreateUser_UserNameReusableAfterDelete equivalent for
// groupNameToID / DeleteGroup.
func TestCreateGroup_DisplayNameReusableAfterDelete(t *testing.T) {
	svc := usecase.NewProvisioningService()
	first, err := svc.CreateGroup("wardline:role-viewer", nil)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := svc.DeleteGroup(first.ID); err != nil {
		t.Fatalf("delete group: %v", err)
	}
	second, err := svc.CreateGroup("wardline:role-viewer", nil)
	if err != nil {
		t.Fatalf("expected \"wardline:role-viewer\" to be reusable after delete, got: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("expected a fresh ID for the recreated group, got the deleted one's ID")
	}
}
