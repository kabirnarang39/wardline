package usecase

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

// ProvisioningService holds SCIM-provisioned Users in memory, keyed by
// ID. UserName is treated as unique (SCIM's own uniqueness constraint on
// that attribute) -- CreateUser rejects a duplicate userName with
// domain.ErrConflict.
type ProvisioningService struct {
	mu    sync.Mutex
	users map[string]domain.User // by ID
}

func NewProvisioningService() *ProvisioningService {
	return &ProvisioningService{users: make(map[string]domain.User)}
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

// GetUserByName is a test/internal convenience -- SCIM's own filter
// query (?filter=userName eq "...") is implemented at the adapter using
// this same lookup, see the adapter's ListUsers handling.
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

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
