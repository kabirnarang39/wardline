package usecase_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
	"github.com/kabirnarang39/wardline/internal/features/approval/usecase"
)

var t0 = time.Unix(0, 0).UTC()

func seqIDs() func() string {
	n := 0
	return func() string {
		n++
		return fmt.Sprintf("id-%d", n)
	}
}

type fakeStore struct {
	reqs   map[string]domain.Request
	grants map[string]domain.Grant
}

func newStore() *fakeStore {
	return &fakeStore{
		reqs:   map[string]domain.Request{},
		grants: map[string]domain.Grant{},
	}
}

func (s *fakeStore) CreateRequest(r domain.Request) error {
	s.reqs[r.ID] = r
	return nil
}

func (s *fakeStore) GetRequest(id string) (domain.Request, bool) {
	r, ok := s.reqs[id]
	return r, ok
}

func (s *fakeStore) ListPending(tenant string) []domain.Request {
	var out []domain.Request
	for _, r := range s.reqs {
		if r.Status == domain.StatusPending && (tenant == "" || r.Tenant == tenant) {
			out = append(out, r)
		}
	}
	return out
}

func (s *fakeStore) DecideRequest(id string, st domain.Status, by string, now time.Time) (domain.Request, error) {
	r, ok := s.reqs[id]
	if !ok || r.Status != domain.StatusPending {
		return domain.Request{}, fmt.Errorf("not pending")
	}
	r.Status, r.DecidedBy, r.DecidedAt = st, by, now
	s.reqs[id] = r
	return r, nil
}

func (s *fakeStore) PutGrant(g domain.Grant) {
	s.grants[g.Key] = g
}

func (s *fakeStore) ConsumeGrant(key string, now time.Time) (domain.Grant, bool) {
	g, ok := s.grants[key]
	if !ok {
		return domain.Grant{}, false
	}
	delete(s.grants, key)
	if now.After(g.ExpiresAt) {
		return domain.Grant{}, false
	}
	return g, true
}

func TestManager_EnqueuesWhenNoGrant(t *testing.T) {
	s := newStore()
	n := 0
	m := usecase.NewManager(s, func() time.Time { return t0 }, 5*time.Minute, func() string {
		n++
		return fmt.Sprintf("id-%d", n)
	})
	res, err := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", map[string]string{"path": "/x"})
	assert.NoError(t, err)
	assert.False(t, res.Approved)
	assert.Equal(t, "id-1", res.PendingID)
	assert.Len(t, s.ListPending("acme"), 1)
}

func TestManager_ApproveMintsSingleUseGrant(t *testing.T) {
	s := newStore()
	m := usecase.NewManager(s, func() time.Time { return t0 }, 5*time.Minute, seqIDs())
	res, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	assert.NoError(t, m.Approve(res.PendingID, "op"))
	// retry: the grant admits exactly one call
	r2, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	assert.True(t, r2.Approved)
	// second retry re-enqueues (single-use consumed)
	r3, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	assert.False(t, r3.Approved)
	assert.NotEmpty(t, r3.PendingID)
}

func TestManager_DenyMintsNoGrant(t *testing.T) {
	s := newStore()
	m := usecase.NewManager(s, func() time.Time { return t0 }, 5*time.Minute, seqIDs())
	res, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	assert.NoError(t, m.Deny(res.PendingID, "op"))
	r2, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	assert.False(t, r2.Approved) // still needs approval, no grant
}

func TestManager_GrantExpires(t *testing.T) {
	s := newStore()
	now := t0
	m := usecase.NewManager(s, func() time.Time { return now }, 1*time.Second, seqIDs())
	res, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	_ = m.Approve(res.PendingID, "op")
	now = t0.Add(2 * time.Second) // past TTL
	r2, _ := m.OnNeedsApproval("acme", "alice", "delete", "tools/call", "sess", nil)
	assert.False(t, r2.Approved)
}
