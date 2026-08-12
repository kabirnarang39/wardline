package usecase

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

// bindingSink is the subset of BindingStore's (and its Postgres-backed
// sibling scimadapter.PostgresBindingStore's) behavior ProvisioningService
// depends on -- a narrow local interface, the same indirection pattern
// rbac/usecase.CompositeAuthorizer's dynamicBindingSource already uses,
// so either sink type can be wired in here with zero further changes to
// either. This is the "second sink type" BindingStore's own doc comment
// anticipated -- scimadapter.PostgresBindingStore (Task 14) is it, so the
// indirection is now due.
type bindingSink interface {
	SetGroupMembers(groupName string, memberUserNames []string)
	RemoveGroup(groupName string)
	Bindings(identity string) (cluster []rbacdomain.ClusterRoleBinding, scoped []rbacdomain.RoleBinding)
}

// ProvisioningService holds SCIM-provisioned Users and Groups in memory,
// keyed by ID. UserName/DisplayName are each treated as unique (SCIM's
// own uniqueness constraint) -- CreateUser/CreateGroup reject a
// duplicate with domain.ErrConflict.
//
// userNameToID/groupNameToID are secondary indices existing purely to
// keep that uniqueness check (and GetUserByName) O(1): without them,
// CreateUser/CreateGroup linear-scanned the whole users/groups map on
// EVERY call while holding s.mu, so provisioning cost grew with total
// resource count and every operation (not just creates) queued behind
// the same growing scan -- O(n) per call, O(n^2) over a provisioning
// run, found by SCIM Bulk load-testing (bench/scimload): create
// throughput visibly degraded as the map grew, not the flat per-op cost
// every other endpoint in this codebase holds. Kept in lockstep with
// users/groups by every mutator (Create/Delete) -- there is no
// mutation path that touches one map without the other.
type ProvisioningService struct {
	mu            sync.Mutex
	users         map[string]domain.User  // by ID
	groups        map[string]domain.Group // by ID
	userNameToID  map[string]string       // userName -> ID
	groupNameToID map[string]string       // displayName -> ID
	bindings      bindingSink
}

func NewProvisioningService() *ProvisioningService {
	return &ProvisioningService{
		users:         make(map[string]domain.User),
		groups:        make(map[string]domain.Group),
		userNameToID:  make(map[string]string),
		groupNameToID: make(map[string]string),
	}
}

// SetBindingStore wires the binding sink every group mutation feeds into
// so RBAC bindings stay derived from current SCIM group membership. nil
// (the zero value) is valid -- group CRUD still works, it just never
// derives any RBAC binding, matching this codebase's "nil means not
// wired" convention (RevokeAuthorizer, AnomalySource, etc).
func (s *ProvisioningService) SetBindingStore(store bindingSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings = store
}

func (s *ProvisioningService) CreateUser(userName string, active bool) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.userNameToID[userName]; exists {
		return domain.User{}, domain.ErrConflict
	}
	id, err := randomID()
	if err != nil {
		return domain.User{}, err
	}
	u := domain.User{ID: id, UserName: userName, Active: active}
	s.users[id] = u
	s.userNameToID[userName] = id
	return u, nil
}

func (s *ProvisioningService) GetUser(id string) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

// GetUserByName is a test/internal convenience for asserting on a
// created User by its unique userName. SCIM's own filter query
// (?filter=userName eq "...") is NOT implemented anywhere yet -- GET
// /scim/v2/Users always returns the full list; the adapter parses no
// query params. That's out of scope this cycle per the design's "no
// filter language beyond eq" cut, and only this method exists to keep
// tests from reaching into ProvisioningService.users directly.
func (s *ProvisioningService) GetUserByName(userName string) (domain.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.userNameToID[userName]
	if !ok {
		return domain.User{}, false
	}
	return s.users[id], true
}

func (s *ProvisioningService) ListUsers() []domain.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

func (s *ProvisioningService) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	delete(s.users, id)
	delete(s.userNameToID, u.UserName)
	// The deleted user's username may still be sitting in one or more
	// groups' Members (by ID, which no longer resolves) or -- since
	// syncBindingLocked pushes by username -- in the BindingStore itself
	// from before this delete. Re-push every group's now-filtered
	// membership so any binding derived from this user is revoked (C1).
	s.resyncAllGroupsLocked()
	return nil
}

func (s *ProvisioningService) PatchUserActive(id string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.Active = active
	s.users[id] = u
	// Deactivating (or reactivating) a user changes which of their
	// groups' memberships should currently be reflected as bindings --
	// re-derive every group so a deactivated user's bindings are
	// revoked immediately, matching this feature's design spec and
	// docs (C1). PATCH active=false is the primary offboarding signal
	// from every IdP this feature targets (Okta, Entra ID).
	s.resyncAllGroupsLocked()
	return nil
}

func (s *ProvisioningService) CreateGroup(displayName string, memberUserIDs []string) (domain.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.groupNameToID[displayName]; exists {
		return domain.Group{}, domain.ErrConflict
	}
	id, err := randomID()
	if err != nil {
		return domain.Group{}, err
	}
	members := make([]string, 0, len(memberUserIDs))
	for _, m := range memberUserIDs {
		if !containsString(members, m) {
			members = append(members, m)
		}
	}
	g := domain.Group{ID: id, DisplayName: displayName, Members: members}
	s.groups[id] = g
	s.groupNameToID[displayName] = id
	s.syncBindingLocked(g)
	return g, nil
}

func (s *ProvisioningService) GetGroup(id string) (domain.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[id]
	if !ok {
		return domain.Group{}, domain.ErrNotFound
	}
	return g, nil
}

func (s *ProvisioningService) ListGroups() []domain.Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g)
	}
	return out
}

func (s *ProvisioningService) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[id]
	if !ok {
		return domain.ErrNotFound
	}
	if s.bindings != nil {
		s.bindings.RemoveGroup(g.DisplayName)
	}
	delete(s.groups, id)
	delete(s.groupNameToID, g.DisplayName)
	return nil
}

// PatchGroupMembers applies a SCIM PATCH "members" add/remove op:
// addUserIDs are unioned in (no duplicates), then removeUserIDs are
// filtered out, and the result is pushed to the wired BindingStore.
func (s *ProvisioningService) PatchGroupMembers(id string, addUserIDs, removeUserIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[id]
	if !ok {
		return domain.ErrNotFound
	}
	members := g.Members
	for _, add := range addUserIDs {
		if !containsString(members, add) {
			members = append(members, add)
		}
	}
	// Fresh backing array -- g.Members (or the pre-add "members" slice
	// above, which may itself still alias g.Members's original array if
	// no add grew it past capacity) may already be held by an external
	// caller via an earlier GetGroup/ListGroups snapshot. Filtering into
	// that same array in place would silently mutate the caller's copy
	// out from under it, unsynchronized. See task-13 fix-round review.
	filtered := make([]string, 0, len(members))
	for _, m := range members {
		if !containsString(removeUserIDs, m) {
			filtered = append(filtered, m)
		}
	}
	g.Members = filtered
	s.groups[id] = g
	s.syncBindingLocked(g)
	return nil
}

// syncBindingLocked pushes g's current membership (resolved from User ID
// to UserName, since BindingStore keys on identity name, not ID) to the
// wired BindingStore. A member ID that doesn't resolve to a known User,
// or that resolves to a User who is not Active, is silently skipped
// rather than erroring -- an IdP is free to reference a User this
// ProvisioningService hasn't seen (yet, or ever), and an inactive member
// must never be granted a binding in the first place (C1: `active` is
// the deprovisioning signal these bindings are derived from). Must be
// called with s.mu held.
func (s *ProvisioningService) syncBindingLocked(g domain.Group) {
	if s.bindings == nil {
		return
	}
	userNames := make([]string, 0, len(g.Members))
	for _, id := range g.Members {
		if u, ok := s.users[id]; ok && u.Active {
			userNames = append(userNames, u.UserName)
		}
	}
	s.bindings.SetGroupMembers(g.DisplayName, userNames)
}

// resyncAllGroupsLocked re-pushes every group's (now Active-filtered)
// membership to the wired BindingStore. Called from PatchUserActive and
// DeleteUser, whose mutation of s.users can change syncBindingLocked's
// filtered output for any group the affected user belongs to, without
// touching s.groups itself. Must be called with s.mu held; lock order
// stays ProvisioningService.mu -> BindingStore.mu, unchanged.
func (s *ProvisioningService) resyncAllGroupsLocked() {
	if s.bindings == nil {
		return
	}
	for _, g := range s.groups {
		s.syncBindingLocked(g)
	}
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
