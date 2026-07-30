package usecase

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

// ProvisioningService holds SCIM-provisioned Users and Groups in memory,
// keyed by ID. UserName/DisplayName are each treated as unique (SCIM's
// own uniqueness constraint) -- CreateUser/CreateGroup reject a
// duplicate with domain.ErrConflict.
type ProvisioningService struct {
	mu       sync.Mutex
	users    map[string]domain.User  // by ID
	groups   map[string]domain.Group // by ID
	bindings *BindingStore
}

func NewProvisioningService() *ProvisioningService {
	return &ProvisioningService{
		users:  make(map[string]domain.User),
		groups: make(map[string]domain.Group),
	}
}

// SetBindingStore wires the BindingStore every group mutation feeds into
// so RBAC bindings stay derived from current SCIM group membership. nil
// (the zero value) is valid -- group CRUD still works, it just never
// derives any RBAC binding, matching this codebase's "nil means not
// wired" convention (RevokeAuthorizer, AnomalySource, etc).
//
// ponytail: BindingStore lives in this same package (scim/usecase), so a
// narrow interface indirection -- the pattern rbac/usecase's
// dynamicBindingSource uses to avoid a cross-package import -- isn't
// needed here until a second sink type shows up.
func (s *ProvisioningService) SetBindingStore(store *BindingStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings = store
}

func (s *ProvisioningService) CreateUser(userName string, active bool) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.UserName == userName {
			return domain.User{}, domain.ErrConflict
		}
	}
	id, err := randomID()
	if err != nil {
		return domain.User{}, err
	}
	u := domain.User{ID: id, UserName: userName, Active: active}
	s.users[id] = u
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
	for _, u := range s.users {
		if u.UserName == userName {
			return u, true
		}
	}
	return domain.User{}, false
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
	if _, ok := s.users[id]; !ok {
		return domain.ErrNotFound
	}
	delete(s.users, id)
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
	return nil
}

func (s *ProvisioningService) CreateGroup(displayName string, memberUserIDs []string) (domain.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.groups {
		if g.DisplayName == displayName {
			return domain.Group{}, domain.ErrConflict
		}
	}
	id, err := randomID()
	if err != nil {
		return domain.Group{}, err
	}
	g := domain.Group{ID: id, DisplayName: displayName, Members: memberUserIDs}
	s.groups[id] = g
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
	filtered := members[:0]
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
// wired BindingStore. A member ID that doesn't resolve to a known User
// is silently skipped rather than erroring -- an IdP is free to reference
// a User this ProvisioningService hasn't seen (yet, or ever) and that
// must not break the rest of the group's binding. Must be called with
// s.mu held.
func (s *ProvisioningService) syncBindingLocked(g domain.Group) {
	if s.bindings == nil {
		return
	}
	userNames := make([]string, 0, len(g.Members))
	for _, id := range g.Members {
		if u, ok := s.users[id]; ok {
			userNames = append(userNames, u.UserName)
		}
	}
	s.bindings.SetGroupMembers(g.DisplayName, userNames)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
