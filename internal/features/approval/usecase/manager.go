package usecase

import (
	"fmt"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/approval/domain"
)

type Result struct {
	Approved  bool
	PendingID string
}

type Manager struct {
	store    domain.Store
	clock    domain.Clock
	grantTTL time.Duration
	newID    func() string
}

func NewManager(store domain.Store, clock domain.Clock, grantTTL time.Duration, newID func() string) *Manager {
	return &Manager{store: store, clock: clock, grantTTL: grantTTL, newID: newID}
}

// OnNeedsApproval admits the call if a single-use grant is present for its
// (tenant, identity, session, tool); otherwise it enqueues a pending request.
func (m *Manager) OnNeedsApproval(tenant, identity, tool, method, session string, params map[string]string) (Result, error) {
	now := m.clock()
	key := grantKey(tenant, identity, session, tool)
	if _, ok := m.store.ConsumeGrant(key, now); ok {
		return Result{Approved: true}, nil
	}
	id := m.newID()
	req := domain.Request{
		ID: id, Identity: identity, Tenant: tenant, Tool: tool, Method: method,
		Params: params, Session: session, CreatedAt: now, Status: domain.StatusPending,
	}
	if err := m.store.CreateRequest(req); err != nil {
		return Result{}, fmt.Errorf("enqueue approval request: %w", err)
	}
	return Result{PendingID: id}, nil
}

func (m *Manager) Approve(id, decidedBy string) error {
	now := m.clock()
	req, err := m.store.DecideRequest(id, domain.StatusApproved, decidedBy, now)
	if err != nil {
		return fmt.Errorf("approve %q: %w", id, err)
	}
	m.store.PutGrant(domain.Grant{
		Key:       grantKey(req.Tenant, req.Identity, req.Session, req.Tool),
		ExpiresAt: now.Add(m.grantTTL),
	})
	return nil
}

func (m *Manager) Deny(id, decidedBy string) error {
	if _, err := m.store.DecideRequest(id, domain.StatusDenied, decidedBy, m.clock()); err != nil {
		return fmt.Errorf("deny %q: %w", id, err)
	}
	return nil
}

func (m *Manager) ListPending(tenant string) []domain.Request {
	return m.store.ListPending(tenant)
}
