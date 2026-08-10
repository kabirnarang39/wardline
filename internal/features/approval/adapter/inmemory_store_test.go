package adapter

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
)

func TestInMemoryStore_CreateListDecide(t *testing.T) {
	s := NewInMemoryStore()
	now := time.Unix(0, 0)
	_ = s.CreateRequest(domain.Request{ID: "1", Tenant: "acme", Status: domain.StatusPending, CreatedAt: now})
	assert.Len(t, s.ListPending("acme"), 1)
	assert.Len(t, s.ListPending("other"), 0)
	assert.Len(t, s.ListPending(""), 1) // "" = all tenants
	r, err := s.DecideRequest("1", domain.StatusApproved, "loopback", now)
	assert.NoError(t, err)
	assert.Equal(t, domain.StatusApproved, r.Status)
	assert.Len(t, s.ListPending("acme"), 0) // no longer pending
}

func TestInMemoryStore_DecideRejectsNonPending(t *testing.T) {
	s := NewInMemoryStore()
	now := time.Unix(0, 0)
	_ = s.CreateRequest(domain.Request{ID: "1", Status: domain.StatusPending, CreatedAt: now})
	_, _ = s.DecideRequest("1", domain.StatusApproved, "op", now)
	_, err := s.DecideRequest("1", domain.StatusDenied, "op", now) // already decided
	assert.Error(t, err)
}

func TestInMemoryStore_GrantSingleUseAndExpiry(t *testing.T) {
	s := NewInMemoryStore()
	now := time.Unix(100, 0)
	s.PutGrant(domain.Grant{Key: "k", ExpiresAt: now.Add(60 * time.Second)})
	_, ok := s.ConsumeGrant("k", now)
	assert.True(t, ok)              // first consume succeeds
	_, ok = s.ConsumeGrant("k", now)
	assert.False(t, ok)             // single-use: gone after first consume
	s.PutGrant(domain.Grant{Key: "k2", ExpiresAt: now.Add(1 * time.Second)})
	_, ok = s.ConsumeGrant("k2", now.Add(2*time.Second))
	assert.False(t, ok)             // expired
}

func TestInMemoryStore_ConcurrentRaceFree(t *testing.T) {
	s := NewInMemoryStore()
	now := time.Unix(0, 0)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := strconv.Itoa(i % 8)
			_ = s.CreateRequest(domain.Request{ID: id, Status: domain.StatusPending, CreatedAt: now})
			_ = s.ListPending("")
			s.PutGrant(domain.Grant{Key: id, ExpiresAt: now.Add(time.Minute)})
			_, _ = s.ConsumeGrant(id, now)
		}(i)
	}
	wg.Wait()
}
